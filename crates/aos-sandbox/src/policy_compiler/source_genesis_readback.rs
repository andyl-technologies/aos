//! Source-purpose signature over actual initial materialization and local ACK.
//!
//! This packet is observation data, never a Root floor or live owner token.
//! Root must verify its independent instance, intent and semantic floor while
//! retaining the original authenticated flight and Controller/Source writers.
//!
//! ```text
//! AOSSGO01 | version:u16=1 | phase:u8 | reserved[5]=0 | nonce[16] |
//! optional-intent[32] | signer-generation:u64 | diagnostic-sequence:u64 |
//! physical-names[48] | receipt[672] | ACK-floor[32] | ACK-record[32] |
//! Ed25519 signature[64]
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::hierarchy::{SourceTreeGenesisReceiptV1, SourceTreeGenesisStateV1};
use crate::journal::ProtectedJournalNamesV1;

use super::source_hold_readback::{PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1};

const MAGIC: &[u8; 8] = b"AOSSGO01";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-tree-genesis.observation.signature.v1\0";
const BODY_BYTES: usize = 864;

#[cfg(target_os = "linux")]
mod intent_context;
#[cfg(target_os = "linux")]
pub use intent_context::{
    SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1, SourceTreeGenesisIntentContextV1,
};

/// Bounds a Source-only genesis observation including its dedicated signature.
pub const SOURCE_TREE_GENESIS_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Correlates a Source observation with one original Root flight.
///
/// An absent intent is valid only for the global Empty probe. Constructing a
/// challenge authenticates no Root sender, intent or mutation authority.
/// Its fresh transport nonce is not the immutable nonce in a durable intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTreeGenesisChallengeV1 {
    nonce: [u8; 16],
    intent: Option<ObjectDigest>,
}

impl SourceTreeGenesisChallengeV1 {
    /// Constructs a nonzero observation nonce and optional nonzero intent.
    ///
    /// # Errors
    ///
    /// Rejects a zero nonce or an explicitly supplied zero intent.
    pub fn new(
        nonce: [u8; 16],
        intent: Option<ObjectDigest>,
    ) -> Result<Self, SourceHoldReadbackErrorV1> {
        if nonce == [0; 16] || intent.is_some_and(|digest| digest.as_bytes() == &[0; 32]) {
            return Err(SourceHoldReadbackErrorV1::NonCanonical);
        }
        Ok(Self { nonce, intent })
    }

    /// Returns the original flight correlation nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the exact intent, absent only for a global Empty probe.
    #[must_use]
    pub const fn intent(self) -> Option<ObjectDigest> {
        self.intent
    }
}

/// Holds authenticated observation data, not current ancestry or Root custody.
pub struct VerifiedSourceTreeGenesisReadbackV1 {
    state: SourceTreeGenesisStateV1,
    receipt: Option<SourceTreeGenesisReceiptV1>,
    names: ProtectedJournalNamesV1,
    sequence: u64,
    ack_floor: Option<ObjectDigest>,
    ack_record: Option<ObjectDigest>,
}

impl VerifiedSourceTreeGenesisReadbackV1 {
    /// Returns the actual signed Empty, Prepared or Anchored observation.
    #[must_use]
    pub const fn state(&self) -> SourceTreeGenesisStateV1 {
        self.state
    }

    /// Borrows the original receipt; absence is only the signed global Empty case.
    #[must_use]
    pub fn receipt(&self) -> Option<&SourceTreeGenesisReceiptV1> {
        self.receipt.as_ref()
    }

    /// Returns the signed original Source directory, journal and lock identities.
    #[must_use]
    pub const fn names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns a diagnostic frame boundary, not a compaction or rollback floor.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact local ACK's Root-floor commitment, if anchored.
    #[must_use]
    pub const fn ack_floor_digest(&self) -> Option<ObjectDigest> {
        self.ack_floor
    }

    /// Returns the exact canonical local ACK commitment, if anchored.
    #[must_use]
    pub const fn ack_record_digest(&self) -> Option<ObjectDigest> {
        self.ack_record
    }
}

/// Verifies the Source role, exact correlation and canonical phase observation.
///
/// The result cannot create a live Root/Controller proof. Empty is a transient
/// signed observation and cannot authorize genesis or reset an existing floor.
///
/// # Errors
///
/// Rejects foreign framing/domain/key/generation, changed nonce or intent,
/// malformed receipt/names, zero diagnostic boundary, or mixed phase padding.
pub fn verify_source_tree_genesis_readback_v1(
    packet: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceTreeGenesisChallengeV1,
) -> Result<VerifiedSourceTreeGenesisReadbackV1, SourceHoldReadbackErrorV1> {
    if packet.len() != SOURCE_TREE_GENESIS_READBACK_BYTES_V1
        || packet.get(..8) != Some(MAGIC)
        || take::<2>(packet, 8)? != 1_u16.to_be_bytes()
        || take::<5>(packet, 11)? != [0; 5]
        || take::<16>(packet, 16)? != challenge.nonce()
        || take::<32>(packet, 32)? != intent_bytes(challenge)
        || take::<8>(packet, 64)? != signer.generation().to_be_bytes()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let names = ProtectedJournalNamesV1::from_bytes(&packet[80..128])
        .map_err(|_| SourceHoldReadbackErrorV1::NonCanonical)?;
    let sequence = u64::from_be_bytes(take::<8>(packet, 72)?);
    if sequence == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let (state, receipt, ack_floor, ack_record) = match packet[10] {
        0 if challenge.intent().is_none()
            && packet[128..BODY_BYTES].iter().all(|byte| *byte == 0) =>
        {
            (SourceTreeGenesisStateV1::Empty, None, None, None)
        }
        phase @ (1 | 2) => {
            let receipt = SourceTreeGenesisReceiptV1::decode(&packet[128..800])
                .map_err(|_| SourceHoldReadbackErrorV1::NonCanonical)?;
            if challenge.intent() != Some(receipt.intent_digest()) {
                return Err(SourceHoldReadbackErrorV1::Stale);
            }
            let floor = take::<32>(packet, 800)?;
            let record = take::<32>(packet, 832)?;
            if phase == 1 && (floor != [0; 32] || record != [0; 32])
                || phase == 2 && (floor == [0; 32] || record == [0; 32])
            {
                return Err(SourceHoldReadbackErrorV1::NonCanonical);
            }
            (
                if phase == 1 {
                    SourceTreeGenesisStateV1::Prepared
                } else {
                    SourceTreeGenesisStateV1::Anchored
                },
                Some(receipt),
                (phase == 2).then_some(ObjectDigest::from_bytes(floor)),
                (phase == 2).then_some(ObjectDigest::from_bytes(record)),
            )
        }
        _ => return Err(SourceHoldReadbackErrorV1::NonCanonical),
    };
    signer
        .verifying_key()
        .verify_strict(
            &signature_preimage(&packet[..BODY_BYTES]),
            &Signature::from_bytes(&take::<64>(packet, BODY_BYTES)?),
        )
        .map_err(|_| SourceHoldReadbackErrorV1::Signature)?;
    Ok(VerifiedSourceTreeGenesisReadbackV1 {
        state,
        receipt,
        names,
        sequence,
        ack_floor,
        ack_record,
    })
}

/// Signs fields only after the existing read-only view replays actual members.
pub(super) fn sign_source_tree_genesis_fields_v1(
    challenge: SourceTreeGenesisChallengeV1,
    names: ProtectedJournalNamesV1,
    sequence: u64,
    receipt: Option<&SourceTreeGenesisReceiptV1>,
    ack: Option<(ObjectDigest, ObjectDigest)>,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if generation == 0
        || sequence == 0
        || receipt.map(SourceTreeGenesisReceiptV1::intent_digest) != challenge.intent()
        || receipt.is_none() && ack.is_some()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let mut packet = [0; SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
    packet[..8].copy_from_slice(MAGIC);
    packet[8..10].copy_from_slice(&1_u16.to_be_bytes());
    packet[10] = if ack.is_some() {
        2
    } else if receipt.is_some() {
        1
    } else {
        0
    };
    packet[16..32].copy_from_slice(&challenge.nonce());
    packet[32..64].copy_from_slice(&intent_bytes(challenge));
    packet[64..72].copy_from_slice(&generation.to_be_bytes());
    packet[72..80].copy_from_slice(&sequence.to_be_bytes());
    packet[80..128].copy_from_slice(&names.to_bytes());
    if let Some(receipt) = receipt {
        packet[128..800].copy_from_slice(&receipt.encode());
    }
    if let Some((floor, record)) = ack {
        if floor.as_bytes() == &[0; 32] || record.as_bytes() == &[0; 32] {
            return Err(SourceHoldReadbackErrorV1::NonCanonical);
        }
        packet[800..832].copy_from_slice(floor.as_bytes());
        packet[832..864].copy_from_slice(record.as_bytes());
    }
    let signature = key.sign(&signature_preimage(&packet[..BODY_BYTES]));
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(packet)
}

fn intent_bytes(challenge: SourceTreeGenesisChallengeV1) -> [u8; 32] {
    challenge
        .intent()
        .map_or([0; 32], |digest| *digest.as_bytes())
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    bytes.extend_from_slice(SIGNATURE_DOMAIN);
    bytes.extend_from_slice(body);
    bytes
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SourceHoldReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(SourceHoldReadbackErrorV1::NonCanonical)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
