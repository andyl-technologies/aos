//! Fixed Source-purpose first-successor readback and signature verification.
//!
//! ```text
//! AOSSSO02 | version2 | phase1 | reserved5 | fresh-nonce16 | Root-intent32 |
//! approval896 | genesis-receipt672 | genesis-ACK192 | receipt536-or-zero |
//! ACK192-or-zero | actual-names48 | sequence8 | signer-generation8 |
//! current-Tree-head32 | current-lineage-head32 | current-Tree32 |
//! current-generation8 | Source-purpose-signature64
//! ```
//!
//! The exact 2784 bytes authenticate comparison DATA only. The fresh challenge
//! does not replace the archived Root nonce/deadline or mint Root authority.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::source_genesis::SourceTreeGenesisReceiptV1;
use crate::hierarchy::source_first_successor_tree_readback_v2;
use crate::journal::{ProtectedJournalNamesV1, ReadOnlyProtectedJournal};

use super::{
    ControllerFirstSourceSuccessorAnchoredFieldsV2, ControllerFirstSourceSuccessorAnchoredV2,
    RootFirstSourceSuccessorFloorFieldsV2, RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorAckV2, SourceFirstSuccessorReceiptV2,
};
use super::source_hold_readback::PinnedSourceHoldReadbackSignerV1;
use super::source_signer_readback::SourceSignerReadbackErrorV1;

/// Bounds the complete Source-purpose observation including its signature.
pub const SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2: usize = 2784;
const BODY_BYTES: usize = SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2 - 64;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-first-successor.source-observation.signature.v2\0";

/// Bounds the explicit mixed-project Source comparison packet.
pub const SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3: usize = 2784;
const MIXED_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-first-successor.source-observation.signature.v3\0";

#[derive(Clone, Copy)]
enum SourceReadbackRecipe {
    SingleProjectV2,
    MixedProjectsV3,
}

impl SourceReadbackRecipe {
    const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::SingleProjectV2 => b"AOSSSO02",
            Self::MixedProjectsV3 => b"AOSSSO03",
        }
    }

    const fn version(self) -> u16 {
        match self {
            Self::SingleProjectV2 => 2,
            Self::MixedProjectsV3 => 3,
        }
    }

    const fn signature_domain(self) -> &'static [u8] {
        match self {
            Self::SingleProjectV2 => SIGNATURE_DOMAIN,
            Self::MixedProjectsV3 => MIXED_SIGNATURE_DOMAIN,
        }
    }
}

/// Selects the actual durable Source phase, not a live cross-owner loan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SourceFirstSuccessorReadbackPhaseV2 {
    /// Observes anchored generation one before any successor append.
    Before = 0,
    /// Observes the exact successor receipt and its pending suffix reserve.
    Prepared = 1,
    /// Observes the exact settled successor ACK.
    Anchored = 2,
}

/// Retains authenticated Source observation DATA, not Root or writer custody.
pub struct VerifiedSourceFirstSuccessorReadbackV2 {
    bytes: [u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2],
    phase: SourceFirstSuccessorReadbackPhaseV2,
    genesis: SourceTreeGenesisReceiptV1,
    genesis_ack_digest: ObjectDigest,
    receipt: Option<SourceFirstSuccessorReceiptV2>,
    ack: Option<SourceFirstSuccessorAckV2>,
    names: ProtectedJournalNamesV1,
    approval: ObjectDigest,
}

impl VerifiedSourceFirstSuccessorReadbackV2 {
    /// Returns the authenticated actual phase DATA.
    pub const fn phase(&self) -> SourceFirstSuccessorReadbackPhaseV2 {
        self.phase
    }

    /// Returns the exact approval commitment DATA.
    pub fn approval(&self) -> ObjectDigest {
        self.approval
    }

    /// Returns the exact original Root intent commitment DATA.
    pub fn root_intent(&self) -> ObjectDigest {
        digest_at(&self.bytes, 32)
    }

    /// Borrows the actual original immutable genesis receipt.
    pub const fn genesis_receipt(&self) -> &SourceTreeGenesisReceiptV1 {
        &self.genesis
    }

    /// Borrows the complete original genesis ACK bytes as nonauthorizing DATA.
    pub fn genesis_ack(&self) -> &[u8] {
        &self.bytes[1632..1824]
    }

    /// Returns the actual original genesis ACK commitment DATA.
    pub const fn genesis_ack_digest(&self) -> ObjectDigest {
        self.genesis_ack_digest
    }

    /// Borrows the actual successor receipt, absent only for Before.
    pub const fn receipt(&self) -> Option<&SourceFirstSuccessorReceiptV2> {
        self.receipt.as_ref()
    }

    /// Borrows the actual settled ACK, absent until Anchored.
    pub const fn ack(&self) -> Option<&SourceFirstSuccessorAckV2> {
        self.ack.as_ref()
    }

    /// Returns the independently observed current physical names DATA.
    pub const fn names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the original native watermark as diagnostic DATA.
    pub fn sequence(&self) -> u64 {
        u64_at(&self.bytes, 2600)
    }

    /// Returns the independently pinned Source-purpose signer generation.
    pub fn signer_generation(&self) -> u64 {
        u64_at(&self.bytes, 2608)
    }

    /// Returns the authenticated current Tree envelope commitment DATA.
    pub fn current_tree_head(&self) -> ObjectDigest {
        digest_at(&self.bytes, 2616)
    }

    /// Returns the authenticated current lineage envelope commitment DATA.
    pub fn current_lineage_head(&self) -> ObjectDigest {
        digest_at(&self.bytes, 2648)
    }

    /// Returns the authenticated canonical current Tree body commitment DATA.
    pub fn current_tree_commit(&self) -> ObjectDigest {
        digest_at(&self.bytes, 2680)
    }

    /// Returns the actual generation, fixed at one or two for this purpose.
    pub fn current_generation(&self) -> u64 {
        u64_at(&self.bytes, 2712)
    }
}

/// Retains explicit mixed-family Source DATA without a strict-v2 conversion.
///
/// The private storage shares only the fixed codec. This type cannot be passed
/// to a strict-v2 Root mutation or Controller authority verifier.
pub struct VerifiedSourceProjectContinuationReadbackV3 {
    data: VerifiedSourceFirstSuccessorReadbackV2,
}

impl VerifiedSourceProjectContinuationReadbackV3 {
    /// Returns the actual selected project phase as comparison DATA.
    pub const fn phase(&self) -> SourceFirstSuccessorReadbackPhaseV2 { self.data.phase() }

    /// Returns the exact signed approval commitment DATA.
    pub fn approval(&self) -> ObjectDigest { self.data.approval() }

    /// Returns the immutable original Root intent commitment DATA.
    pub fn root_intent(&self) -> ObjectDigest { self.data.root_intent() }

    /// Borrows the actual selected genesis receipt DATA.
    pub const fn genesis_receipt(&self) -> &SourceTreeGenesisReceiptV1 { self.data.genesis_receipt() }

    /// Borrows the actual selected genesis ACK bytes DATA.
    pub fn genesis_ack(&self) -> &[u8] { self.data.genesis_ack() }

    /// Returns the actual selected genesis ACK commitment DATA.
    pub const fn genesis_ack_digest(&self) -> ObjectDigest { self.data.genesis_ack_digest() }

    /// Borrows the selected successor receipt DATA, if present.
    pub const fn receipt(&self) -> Option<&SourceFirstSuccessorReceiptV2> { self.data.receipt() }

    /// Borrows the selected settled ACK DATA, if present.
    pub const fn ack(&self) -> Option<&SourceFirstSuccessorAckV2> { self.data.ack() }

    /// Returns the independently observed current physical names DATA.
    pub const fn names(&self) -> ProtectedJournalNamesV1 { self.data.names() }

    /// Returns the original native watermark DATA.
    pub fn sequence(&self) -> u64 { self.data.sequence() }

    /// Returns the independently pinned Source-purpose signer generation.
    pub fn signer_generation(&self) -> u64 { self.data.signer_generation() }

    /// Returns the selected current Tree envelope commitment DATA.
    pub fn current_tree_head(&self) -> ObjectDigest { self.data.current_tree_head() }

    /// Returns the selected current lineage envelope commitment DATA.
    pub fn current_lineage_head(&self) -> ObjectDigest { self.data.current_lineage_head() }

    /// Returns the selected canonical current Tree body commitment DATA.
    pub fn current_tree_commit(&self) -> ObjectDigest { self.data.current_tree_commit() }

    /// Returns the selected current generation DATA.
    pub fn current_generation(&self) -> u64 { self.data.current_generation() }
}

/// Authenticates a fixed Source observation against a separately pinned key.
///
/// # Errors
/// Rejects changed framing, challenge, original intent, nested records, phase,
/// signer generation, physical joins or Source-purpose signature. Success is
/// still DATA and cannot replace the actual held cross-owner loans.
pub fn verify_source_first_successor_readback_v2(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
) -> Result<VerifiedSourceFirstSuccessorReadbackV2, SourceGenesisErrorV1> {
    let verified = decode(packet, fresh_nonce, context)?;
    if verified.signer_generation() != signer.generation() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    signer.verifying_key().verify_strict(&signature_message(&packet[..BODY_BYTES]),
        &Signature::from_bytes(&array_at(packet, BODY_BYTES)))
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    Ok(verified)
}

/// Authenticates only an explicitly framed mixed-project Source observation.
///
/// # Errors
/// Rejects a strict-v2 packet, changed challenge/context, malformed selected
/// joins, unpinned signer generation or invalid v3-purpose signature.
pub fn verify_source_project_continuation_readback_v3(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
) -> Result<VerifiedSourceProjectContinuationReadbackV3, SourceGenesisErrorV1> {
    let data = decode_with_recipe(packet, fresh_nonce, context, SourceReadbackRecipe::MixedProjectsV3)?;
    if data.signer_generation() != signer.generation() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    signer.verifying_key().verify_strict(
        &signature_message_with_recipe(&packet[..BODY_BYTES], SourceReadbackRecipe::MixedProjectsV3),
        &Signature::from_bytes(&array_at(packet, BODY_BYTES)),
    ).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    Ok(VerifiedSourceProjectContinuationReadbackV3 { data })
}

/// Signs only actual replay from the existing fixed read-only Source view.
#[cfg(target_os = "linux")]
pub(super) fn sign_source_first_successor_from_view_v2(
    readback: &mut ReadOnlyProtectedJournal, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2], SourceSignerReadbackErrorV1> {
    sign_source_successor_from_view(
        readback, fresh_nonce, context, signer_generation, signing_key,
        SourceReadbackRecipe::SingleProjectV2,
    )
}

#[cfg(target_os = "linux")]
pub(super) fn sign_source_project_continuation_from_view_v3(
    readback: &mut ReadOnlyProtectedJournal, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3], SourceSignerReadbackErrorV1> {
    sign_source_successor_from_view(
        readback, fresh_nonce, context, signer_generation, signing_key,
        SourceReadbackRecipe::MixedProjectsV3,
    )
}

#[cfg(target_os = "linux")]
fn sign_source_successor_from_view(
    readback: &mut ReadOnlyProtectedJournal, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey, recipe: SourceReadbackRecipe,
) -> Result<[u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2], SourceSignerReadbackErrorV1> {
    if fresh_nonce == [0; 16] || signer_generation == 0 {
        return Err(SourceGenesisErrorV1::NonCanonical.into());
    }
    let names = readback.physical_names_v1();
    let journal = readback.journal_mut();
    let sequence = journal.snapshot_sequence();
    let successor = match recipe {
        SourceReadbackRecipe::SingleProjectV2 => journal.source_first_successor_rows_v2()?,
        SourceReadbackRecipe::MixedProjectsV3 => journal.source_project_continuation_rows_v3(Some(context.project()))?,
    };
    let genesis = journal.source_tree_genesis_rows_v1()?;
    let (tree_head, lineage_head, tree_commit, generation) =
        source_first_successor_tree_readback_v2(journal, context.project())
            .map_err(SourceGenesisErrorV1::from)?;
    let original = genesis.receipts.get(&context.project()).ok_or(SourceGenesisErrorV1::Conflict)?;
    let original_ack = genesis.acks.get(&context.project()).ok_or(SourceGenesisErrorV1::Conflict)?;
    if genesis.pending.is_some()
        || (matches!(recipe, SourceReadbackRecipe::SingleProjectV2)
            && successor.receipts.keys().any(|project| *project != context.project()))
    {
        return Err(SourceGenesisErrorV1::Conflict.into());
    }
    let receipt = successor.receipts.get(&context.project());
    let ack = successor.acks.get(&context.project());
    let phase = match (receipt, ack) {
        (None, None) => {
            if matches!(recipe, SourceReadbackRecipe::SingleProjectV2) {
                super::super::hierarchy::source_genesis::validate_actual_rows(journal)?;
            }
            SourceFirstSuccessorReadbackPhaseV2::Before
        }
        (Some(_), None) => SourceFirstSuccessorReadbackPhaseV2::Prepared,
        (Some(_), Some(_)) => SourceFirstSuccessorReadbackPhaseV2::Anchored,
        (None, Some(_)) => return Err(SourceGenesisErrorV1::Conflict.into()),
    };
    if successor.pending.as_ref().is_some_and(|pending| pending.source_names() != names) {
        return Err(SourceGenesisErrorV1::Stale.into());
    }

    let mut packet = [0; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2];
    packet[..8].copy_from_slice(recipe.magic());
    packet[8..10].copy_from_slice(&recipe.version().to_be_bytes());
    packet[10] = phase as u8;
    packet[16..32].copy_from_slice(&fresh_nonce);
    packet[32..64].copy_from_slice(context.digest().as_bytes());
    packet[64..960].copy_from_slice(context.approval_packet().as_bytes());
    packet[960..1632].copy_from_slice(&original.encode());
    packet[1632..1824].copy_from_slice(&original_ack.encode());
    if let Some(receipt) = receipt {
        packet[1824..2360].copy_from_slice(receipt.as_bytes());
    }
    if let Some(ack) = ack {
        packet[2360..2552].copy_from_slice(ack.as_bytes());
    }
    packet[2552..2600].copy_from_slice(&names.to_bytes());
    packet[2600..2608].copy_from_slice(&sequence.to_be_bytes());
    packet[2608..2616].copy_from_slice(&signer_generation.to_be_bytes());
    packet[2616..2648].copy_from_slice(tree_head.as_bytes());
    packet[2648..2680].copy_from_slice(lineage_head.as_bytes());
    packet[2680..2712].copy_from_slice(tree_commit.as_bytes());
    packet[2712..2720].copy_from_slice(&generation.to_be_bytes());
    // Pure DATA shape/bindings precede real signing. Only the public verifier
    // authenticates the complete signature against the independent pinned key.
    decode_with_recipe(&packet, fresh_nonce, context, recipe)?;
    let signature = signing_key.sign(&signature_message_with_recipe(&packet[..BODY_BYTES], recipe)).to_bytes();
    packet[BODY_BYTES..].copy_from_slice(&signature);
    if journal.snapshot_sequence() != sequence {
        return Err(SourceGenesisErrorV1::Stale.into());
    }
    Ok(packet)
}

fn decode(packet: &[u8], fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2)
    -> Result<VerifiedSourceFirstSuccessorReadbackV2, SourceGenesisErrorV1>
{
    decode_with_recipe(packet, fresh_nonce, context, SourceReadbackRecipe::SingleProjectV2)
}

fn decode_with_recipe(
    packet: &[u8], fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    recipe: SourceReadbackRecipe,
) -> Result<VerifiedSourceFirstSuccessorReadbackV2, SourceGenesisErrorV1> {
    if packet.len() != SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2
        || &packet[..8] != recipe.magic() || packet[8..10] != recipe.version().to_be_bytes()
        || packet[11..16] != [0; 5] || fresh_nonce == [0; 16]
        || packet[16..32] != fresh_nonce || packet[32..64] != *context.digest().as_bytes()
        || packet[64..960] != *context.approval_packet().as_bytes()
        || u64_at(packet, 2600) == 0 || u64_at(packet, 2608) == 0
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let phase = match packet[10] {
        0 => SourceFirstSuccessorReadbackPhaseV2::Before,
        1 => SourceFirstSuccessorReadbackPhaseV2::Prepared,
        2 => SourceFirstSuccessorReadbackPhaseV2::Anchored,
        _ => return Err(SourceGenesisErrorV1::NonCanonical),
    };
    let genesis = SourceTreeGenesisReceiptV1::decode(&packet[960..1632])?;
    let genesis_ack = crate::journal::source_tree_genesis::SourceGenesisAckV1::decode(&packet[1632..1824])?;
    let names = ProtectedJournalNamesV1::from_bytes(&packet[2552..2600])?;
    if genesis.instance() != context.instance() || genesis.project() != context.project()
        || genesis.tree_head() != context.old_tree_head() || genesis.lineage_head() != context.old_lineage_head()
        || genesis_ack.instance != context.instance() || genesis_ack.project != context.project()
        || genesis_ack.receipt != genesis.digest() || genesis_ack.root_floor != context.predecessor_floor()
        || [2616, 2648, 2680].into_iter().any(|offset| packet[offset..offset + 32] == [0; 32])
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let receipt = if phase == SourceFirstSuccessorReadbackPhaseV2::Before {
        if packet[1824..2552] != [0; 728] || names != context.source_names()
            || digest_at(packet, 2616) != context.old_tree_head()
            || digest_at(packet, 2648) != context.old_lineage_head()
            || packet[2680..2712] != context.approval_packet().as_bytes()[600..632]
            || u64_at(packet, 2712) != 1
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        None
    } else {
        let receipt = SourceFirstSuccessorReceiptV2::decode(&packet[1824..2360])?;
        crate::hierarchy::require_first_successor_context_v2(&receipt, context)?;
        if digest_at(packet, 2616) != receipt.next_tree_head()
            || digest_at(packet, 2648) != receipt.next_lineage_head()
            || digest_at(packet, 2680) != receipt.next_tree_commit() || u64_at(packet, 2712) != 2
            || (phase == SourceFirstSuccessorReadbackPhaseV2::Prepared && names != receipt.source_names())
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        Some(receipt)
    };
    let ack = if phase == SourceFirstSuccessorReadbackPhaseV2::Anchored {
        let receipt = receipt.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let ack = SourceFirstSuccessorAckV2::decode(&packet[2360..2552])?;
        let floor = RootFirstSourceSuccessorFloorV2::new(RootFirstSourceSuccessorFloorFieldsV2 {
            predecessor_floor: receipt.predecessor_floor(), approval: receipt.approval(),
            receipt: receipt.clone(), roles: receipt.roles(),
        })?;
        let anchored = ControllerFirstSourceSuccessorAnchoredV2::new(ControllerFirstSourceSuccessorAnchoredFieldsV2 {
            approval: receipt.approval(), receipt: receipt.digest(), floor: floor.digest(),
        })?;
        if ack.instance() != receipt.instance() || ack.project() != receipt.project()
            || ack.receipt() != receipt.digest() || ack.root_floor() != floor.digest()
            || ack.controller_anchored() != anchored.digest()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        Some(ack)
    } else {
        if packet[2360..2552] != [0; 192] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        None
    };
    Ok(VerifiedSourceFirstSuccessorReadbackV2 {
        bytes: array_at(packet, 0), phase, genesis, genesis_ack_digest: genesis_ack.digest(),
        receipt, ack, names, approval: context.approval(),
    })
}

fn signature_message(body: &[u8]) -> Vec<u8> {
    signature_message_with_recipe(body, SourceReadbackRecipe::SingleProjectV2)
}

fn signature_message_with_recipe(body: &[u8], recipe: SourceReadbackRecipe) -> Vec<u8> {
    let domain = recipe.signature_domain();
    let mut message = Vec::with_capacity(domain.len() + body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    message
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut array = [0; N];
    array.copy_from_slice(&bytes[offset..offset + N]);
    array
}

fn digest_at(bytes: &[u8], offset: usize) -> ObjectDigest {
    ObjectDigest::from_bytes(array_at(bytes, offset))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(array_at(bytes, offset))
}

#[cfg(test)]
mod signature_domain_regression_tests {
    use super::{
        BODY_BYTES, SourceReadbackRecipe, signature_message, signature_message_with_recipe,
    };

    #[test]
    fn observation_versions_keep_distinct_exact_prefixes_over_the_same_body() {
        let body = [0xa5; BODY_BYTES];
        let v2_domain = b"aos.sandbox.source-first-successor.source-observation.signature.v2\0";
        let v3_domain = b"aos.sandbox.source-first-successor.source-observation.signature.v3\0";

        let v2 = signature_message(&body);
        let v3 = signature_message_with_recipe(&body, SourceReadbackRecipe::MixedProjectsV3);

        assert_eq!(BODY_BYTES, 2720);
        assert_eq!(v2.len(), v2_domain.len() + body.len());
        assert_eq!(v3.len(), v3_domain.len() + body.len());
        assert_eq!(&v2[..v2_domain.len()], v2_domain);
        assert_eq!(&v3[..v3_domain.len()], v3_domain);
        assert_eq!(&v2[v2_domain.len()..], &body);
        assert_eq!(&v3[v3_domain.len()..], &body);
        assert_ne!(v2, v3);
    }
}
