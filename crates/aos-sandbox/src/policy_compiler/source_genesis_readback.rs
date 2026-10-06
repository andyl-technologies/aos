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

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::hierarchy::{SourceTreeGenesisReceiptV1, SourceTreeGenesisStateV1};
use crate::journal::ProtectedJournalNamesV1;

use super::source_hold_readback::{PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1};

const MAGIC: &[u8; 8] = b"AOSSGO01";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-tree-genesis.observation.signature.v1\0";
const BODY_BYTES: usize = 864;

#[derive(Clone, Copy)]
enum GenesisReadbackRecipe {
    StrictV1,
    ProjectV3 { project: ProjectId, vacant_instance: Option<[u8; 32]> },
}

impl GenesisReadbackRecipe {
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::StrictV1 => MAGIC,
            Self::ProjectV3 { .. } => b"AOSSGO03",
        }
    }

    fn version(self) -> u16 {
        match self { Self::StrictV1 => 1, Self::ProjectV3 { .. } => 3 }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::StrictV1 => SIGNATURE_DOMAIN,
            Self::ProjectV3 { .. } => b"aos.sandbox.source-tree-genesis.mixed-observation.signature.v3\0",
        }
    }
}

#[cfg(target_os = "linux")]
mod intent_context;
#[cfg(target_os = "linux")]
pub use intent_context::{
    SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1, SourceTreeGenesisIntentContextV1,
};

/// Bounds a Source-only genesis observation including its dedicated signature.
pub const SOURCE_TREE_GENESIS_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Bounds the distinct approval-free mixed initial-project observation.
pub const SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3: usize = BODY_BYTES + 64;

/// Correlates an explicit project observation without supplying admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceProjectGenesisChallengeV3 {
    original: SourceTreeGenesisChallengeV1,
    project: ProjectId,
}

impl SourceProjectGenesisChallengeV3 {
    /// Constructs project and nonce comparison DATA for the closed mixed purpose.
    ///
    /// # Errors
    /// Rejects sentinel project, nonce or explicitly zero intent commitment.
    pub fn new(
        nonce: [u8; 16], project: ProjectId, intent: Option<ObjectDigest>,
    ) -> Result<Self, SourceHoldReadbackErrorV1> {
        if project.as_bytes() == &[0; 16] {
            return Err(SourceHoldReadbackErrorV1::NonCanonical);
        }
        Ok(Self { original: SourceTreeGenesisChallengeV1::new(nonce, intent)?, project })
    }

    /// Returns the explicitly selected comparison project.
    pub const fn project(self) -> ProjectId { self.project }

    /// Returns the fresh observation nonce, not a persisted admission nonce.
    pub const fn nonce(self) -> [u8; 16] { self.original.nonce() }

    /// Returns the actual original receipt intent commitment, absent for vacancy.
    pub const fn intent(self) -> Option<ObjectDigest> { self.original.intent() }
}

/// Holds verified mixed genesis DATA, never a live floor or strict owner loan.
pub struct VerifiedSourceProjectGenesisReadbackV3 {
    observed: VerifiedSourceTreeGenesisReadbackV1,
    project: ProjectId,
    instance: [u8; 32],
}

impl VerifiedSourceProjectGenesisReadbackV3 {
    /// Returns the explicitly signed selected project.
    pub const fn project(&self) -> ProjectId { self.project }

    /// Returns the actual common existing instance signed by the independent reader.
    pub const fn instance(&self) -> [u8; 32] { self.instance }

    /// Returns selected Vacant, Prepared or Anchored phase DATA.
    pub const fn state(&self) -> SourceTreeGenesisStateV1 { self.observed.state() }

    /// Borrows the actual original receipt, absent only for selected vacancy.
    pub fn receipt(&self) -> Option<&SourceTreeGenesisReceiptV1> { self.observed.receipt() }

    /// Returns the signed actual reader's physical names.
    pub const fn names(&self) -> ProtectedJournalNamesV1 { self.observed.names() }

    /// Returns diagnostic original watermark DATA.
    pub const fn journal_sequence(&self) -> u64 { self.observed.journal_sequence() }

    /// Returns the actual original Root floor ACK, if anchored.
    pub const fn ack_floor_digest(&self) -> Option<ObjectDigest> { self.observed.ack_floor_digest() }

    /// Returns the actual canonical Source ACK commitment, if anchored.
    pub const fn ack_record_digest(&self) -> Option<ObjectDigest> { self.observed.ack_record_digest() }
}

/// Verifies only the closed approval-free mixed-project signature recipe.
///
/// # Errors
/// Rejects old-purpose packets, changed project/nonce/intent, wrong independent
/// role signature, malformed vacancy or receipt, and foreign phase padding.
pub fn verify_source_project_genesis_readback_v3(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceProjectGenesisChallengeV3,
) -> Result<VerifiedSourceProjectGenesisReadbackV3, SourceHoldReadbackErrorV1> {
    let observed = verify_genesis_with_recipe(packet, signer, challenge.original,
        GenesisReadbackRecipe::ProjectV3 { project: challenge.project, vacant_instance: None })?;
    let instance = if let Some(receipt) = observed.receipt() {
        if receipt.project() != challenge.project {
            return Err(SourceHoldReadbackErrorV1::Stale);
        }
        receipt.instance()
    } else {
        take(packet, 144)?
    };
    Ok(VerifiedSourceProjectGenesisReadbackV3 { observed, project: challenge.project, instance })
}

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
    verify_genesis_with_recipe(packet, signer, challenge, GenesisReadbackRecipe::StrictV1)
}

fn verify_genesis_with_recipe(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceTreeGenesisChallengeV1, recipe: GenesisReadbackRecipe,
) -> Result<VerifiedSourceTreeGenesisReadbackV1, SourceHoldReadbackErrorV1> {
    if packet.len() != SOURCE_TREE_GENESIS_READBACK_BYTES_V1
        || packet.get(..8) != Some(recipe.magic())
        || take::<2>(packet, 8)? != recipe.version().to_be_bytes()
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
        0 if matches!(recipe, GenesisReadbackRecipe::StrictV1) && challenge.intent().is_none()
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
        3 if challenge.intent().is_none()
            && matches!(recipe, GenesisReadbackRecipe::ProjectV3 { project, .. }
                if packet[128..144] == *project.as_bytes())
            && packet[144..176] != [0; 32]
            && packet[176..BODY_BYTES].iter().all(|byte| *byte == 0) =>
        {
            (SourceTreeGenesisStateV1::VacantProject, None, None, None)
        }
        _ => return Err(SourceHoldReadbackErrorV1::NonCanonical),
    };
    signer
        .verifying_key()
        .verify_strict(
            &signature_preimage_with_recipe(&packet[..BODY_BYTES], recipe),
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
    sign_genesis_with_recipe(challenge, names, sequence, receipt, ack, generation, key,
        GenesisReadbackRecipe::StrictV1)
}

pub(super) fn sign_source_project_genesis_fields_v3(
    challenge: SourceProjectGenesisChallengeV3, names: ProtectedJournalNamesV1,
    sequence: u64, receipt: Option<&SourceTreeGenesisReceiptV1>,
    ack: Option<(ObjectDigest, ObjectDigest)>, instance: [u8; 32],
    generation: u64, key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3], SourceHoldReadbackErrorV1> {
    if instance == [0; 32]
        || receipt.is_some_and(|receipt| receipt.project() != challenge.project
            || receipt.instance() != instance)
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    sign_genesis_with_recipe(challenge.original, names, sequence, receipt, ack, generation, key,
        GenesisReadbackRecipe::ProjectV3 { project: challenge.project, vacant_instance: Some(instance) })
}

fn sign_genesis_with_recipe(
    challenge: SourceTreeGenesisChallengeV1, names: ProtectedJournalNamesV1,
    sequence: u64, receipt: Option<&SourceTreeGenesisReceiptV1>,
    ack: Option<(ObjectDigest, ObjectDigest)>, generation: u64,
    key: &SigningKey, recipe: GenesisReadbackRecipe,
) -> Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if generation == 0
        || sequence == 0
        || receipt.map(SourceTreeGenesisReceiptV1::intent_digest) != challenge.intent()
        || receipt.is_none() && ack.is_some()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let mut packet = [0; SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
    packet[..8].copy_from_slice(recipe.magic());
    packet[8..10].copy_from_slice(&recipe.version().to_be_bytes());
    packet[10] = if ack.is_some() {
        2
    } else if receipt.is_some() {
        1
    } else {
        match recipe { GenesisReadbackRecipe::StrictV1 => 0, GenesisReadbackRecipe::ProjectV3 { .. } => 3 }
    };
    packet[16..32].copy_from_slice(&challenge.nonce());
    packet[32..64].copy_from_slice(&intent_bytes(challenge));
    packet[64..72].copy_from_slice(&generation.to_be_bytes());
    packet[72..80].copy_from_slice(&sequence.to_be_bytes());
    packet[80..128].copy_from_slice(&names.to_bytes());
    if let Some(receipt) = receipt {
        packet[128..800].copy_from_slice(&receipt.encode());
    } else if let GenesisReadbackRecipe::ProjectV3 { project, vacant_instance } = recipe {
        let instance = vacant_instance.filter(|instance| *instance != [0; 32])
            .ok_or(SourceHoldReadbackErrorV1::NonCanonical)?;
        packet[128..144].copy_from_slice(project.as_bytes());
        packet[144..176].copy_from_slice(&instance);
    }
    if let Some((floor, record)) = ack {
        if floor.as_bytes() == &[0; 32] || record.as_bytes() == &[0; 32] {
            return Err(SourceHoldReadbackErrorV1::NonCanonical);
        }
        packet[800..832].copy_from_slice(floor.as_bytes());
        packet[832..864].copy_from_slice(record.as_bytes());
    }
    let signature = key.sign(&signature_preimage_with_recipe(&packet[..BODY_BYTES], recipe));
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(packet)
}

fn intent_bytes(challenge: SourceTreeGenesisChallengeV1) -> [u8; 32] {
    challenge
        .intent()
        .map_or([0; 32], |digest| *digest.as_bytes())
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    signature_preimage_with_recipe(body, GenesisReadbackRecipe::StrictV1)
}

fn signature_preimage_with_recipe(body: &[u8], recipe: GenesisReadbackRecipe) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(recipe.domain().len() + body.len());
    bytes.extend_from_slice(recipe.domain());
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
