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
//! Resource purposes AOSSSO04/05 retain approval1072 and independently decoded
//! historical genesis672/848, yielding exact packets2960/3136. The legacy
//! purposes retain their exact 2784 bytes and distinct signature domains.
//!
//! These bytes authenticate comparison DATA only. The fresh challenge
//! does not replace the archived Root nonce/deadline or mint Root authority.

use std::borrow::Cow;

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
#[cfg(test)]
const BODY_BYTES: usize = SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2 - 64;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-first-successor.source-observation.signature.v2\0";

/// Bounds the explicit mixed-project Source comparison packet.
pub const SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3: usize = 2784;
const MIXED_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-first-successor.source-observation.signature.v3\0";

/// Bounds a full-resource observation retaining a historical legacy genesis.
pub const SOURCE_RESOURCE_SUCCESSOR_LEGACY_GENESIS_BYTES_V4: usize = 2960;

/// Bounds a full-resource observation retaining a full-resource genesis.
pub const SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4: usize = 3136;

const RESOURCE_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-first-successor.source-observation.signature.v4\0";
const RESOURCE_MIXED_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-first-successor.source-observation.signature.v5\0";

#[derive(Clone, Copy)]
enum SourceReadbackRecipe {
    SingleProjectV2,
    MixedProjectsV3,
    ResourceSingleProjectV4,
    ResourceMixedProjectsV5,
}

impl SourceReadbackRecipe {
    const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::SingleProjectV2 => b"AOSSSO02",
            Self::MixedProjectsV3 => b"AOSSSO03",
            Self::ResourceSingleProjectV4 => b"AOSSSO04",
            Self::ResourceMixedProjectsV5 => b"AOSSSO05",
        }
    }

    const fn version(self) -> u16 {
        match self {
            Self::SingleProjectV2 => 2,
            Self::MixedProjectsV3 => 3,
            Self::ResourceSingleProjectV4 => 4,
            Self::ResourceMixedProjectsV5 => 5,
        }
    }

    const fn signature_domain(self) -> &'static [u8] {
        match self {
            Self::SingleProjectV2 => SIGNATURE_DOMAIN,
            Self::MixedProjectsV3 => MIXED_SIGNATURE_DOMAIN,
            Self::ResourceSingleProjectV4 => RESOURCE_SIGNATURE_DOMAIN,
            Self::ResourceMixedProjectsV5 => RESOURCE_MIXED_SIGNATURE_DOMAIN,
        }
    }

    const fn is_resource(self) -> bool {
        matches!(self, Self::ResourceSingleProjectV4 | Self::ResourceMixedProjectsV5)
    }

    const fn is_single_project(self) -> bool {
        matches!(self, Self::SingleProjectV2 | Self::ResourceSingleProjectV4)
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
    bytes: Vec<u8>,
    phase: SourceFirstSuccessorReadbackPhaseV2,
    genesis: SourceTreeGenesisReceiptV1,
    genesis_ack_digest: ObjectDigest,
    receipt: Option<SourceFirstSuccessorReceiptV2>,
    ack: Option<SourceFirstSuccessorAckV2>,
    names: ProtectedJournalNamesV1,
    approval: ObjectDigest,
}

// The sole decoder lends validated DATA fields without copying the complete
// packet. Signing may reuse its already validated journal genesis receipt;
// verification owns its decoded receipt and materializes the retained packet.
struct ValidatedSourceReadbackFields<'data> {
    bytes: &'data [u8],
    phase: SourceFirstSuccessorReadbackPhaseV2,
    genesis: Cow<'data, SourceTreeGenesisReceiptV1>,
    genesis_ack_digest: ObjectDigest,
    receipt: Option<SourceFirstSuccessorReceiptV2>,
    ack: Option<SourceFirstSuccessorAckV2>,
    names: ProtectedJournalNamesV1,
    approval: ObjectDigest,
}

impl ValidatedSourceReadbackFields<'_> {
    fn into_verified_data(self) -> VerifiedSourceFirstSuccessorReadbackV2 {
        VerifiedSourceFirstSuccessorReadbackV2 {
            bytes: self.bytes.to_vec(),
            phase: self.phase,
            genesis: self.genesis.into_owned(),
            genesis_ack_digest: self.genesis_ack_digest,
            receipt: self.receipt,
            ack: self.ack,
            names: self.names,
            approval: self.approval,
        }
    }
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
        let offset = self.tail_offset();
        &self.bytes[offset..offset + 192]
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
        u64_at(&self.bytes, self.tail_offset() + 968)
    }

    /// Returns the independently pinned Source-purpose signer generation.
    pub fn signer_generation(&self) -> u64 {
        u64_at(&self.bytes, self.tail_offset() + 976)
    }

    /// Returns the authenticated current Tree envelope commitment DATA.
    pub fn current_tree_head(&self) -> ObjectDigest {
        digest_at(&self.bytes, self.tail_offset() + 984)
    }

    /// Returns the authenticated current lineage envelope commitment DATA.
    pub fn current_lineage_head(&self) -> ObjectDigest {
        digest_at(&self.bytes, self.tail_offset() + 1016)
    }

    /// Returns the authenticated canonical current Tree body commitment DATA.
    pub fn current_tree_commit(&self) -> ObjectDigest {
        digest_at(&self.bytes, self.tail_offset() + 1048)
    }

    /// Returns the actual generation, fixed at one or two for this purpose.
    pub fn current_generation(&self) -> u64 {
        u64_at(&self.bytes, self.tail_offset() + 1080)
    }

    fn tail_offset(&self) -> usize {
        self.bytes.len() - 1152
    }
}

/// Retains explicit mixed-family Source DATA without a strict-v2 conversion.
///
/// The private storage shares only the bounded versioned codec. This type
/// cannot be passed
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
    verify_with_recipe(packet, signer, fresh_nonce, context, SourceReadbackRecipe::SingleProjectV2)
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
    let data = verify_with_recipe(packet, signer, fresh_nonce, context, SourceReadbackRecipe::MixedProjectsV3)?;
    Ok(VerifiedSourceProjectContinuationReadbackV3 { data })
}

/// Authenticates a full-resource single-project Source observation.
///
/// # Errors
/// Rejects legacy framing, truncated authorization, malformed historical
/// genesis joins, changed challenge/context or an invalid pinned signature.
pub fn verify_source_resource_first_successor_readback_v4(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
) -> Result<VerifiedSourceFirstSuccessorReadbackV2, SourceGenesisErrorV1> {
    verify_with_recipe(packet, signer, fresh_nonce, context, SourceReadbackRecipe::ResourceSingleProjectV4)
}

/// Authenticates a full-resource mixed-project Source observation.
///
/// # Errors
/// Rejects legacy or single-project framing, changed challenge/context,
/// malformed full-family joins or an invalid pinned signature.
pub fn verify_source_resource_project_continuation_readback_v5(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
) -> Result<VerifiedSourceProjectContinuationReadbackV3, SourceGenesisErrorV1> {
    let data = verify_with_recipe(packet, signer, fresh_nonce, context, SourceReadbackRecipe::ResourceMixedProjectsV5)?;
    Ok(VerifiedSourceProjectContinuationReadbackV3 { data })
}

fn verify_with_recipe(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    recipe: SourceReadbackRecipe,
) -> Result<VerifiedSourceFirstSuccessorReadbackV2, SourceGenesisErrorV1> {
    let data = decode_with_recipe(packet, fresh_nonce, context, recipe, None)?.into_verified_data();
    if data.signer_generation() != signer.generation() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let body_bytes = packet.len() - 64;
    signer.verifying_key().verify_strict(
        &signature_message_with_recipe(&packet[..body_bytes], recipe),
        &Signature::from_bytes(&array_at(packet, body_bytes)),
    ).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    Ok(data)
}

/// Signs only actual replay from the existing fixed read-only Source view.
#[cfg(target_os = "linux")]
pub(super) fn sign_source_first_successor_from_view_v2(
    readback: &mut ReadOnlyProtectedJournal, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2], SourceSignerReadbackErrorV1> {
    if context.approval_packet().has_resource_authorization() {
        return Err(SourceGenesisErrorV1::NonCanonical.into());
    }
    sign_source_successor_from_view(
        readback, fresh_nonce, context, signer_generation, signing_key,
        SourceReadbackRecipe::SingleProjectV2,
    )?.try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical.into())
}

#[cfg(target_os = "linux")]
pub(super) fn sign_source_project_continuation_from_view_v3(
    readback: &mut ReadOnlyProtectedJournal, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3], SourceSignerReadbackErrorV1> {
    if context.approval_packet().has_resource_authorization() {
        return Err(SourceGenesisErrorV1::NonCanonical.into());
    }
    sign_source_successor_from_view(
        readback, fresh_nonce, context, signer_generation, signing_key,
        SourceReadbackRecipe::MixedProjectsV3,
    )?.try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical.into())
}

#[cfg(target_os = "linux")]
pub(super) fn sign_source_resource_successor_from_view(
    readback: &mut ReadOnlyProtectedJournal, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey, mixed: bool,
) -> Result<Vec<u8>, SourceSignerReadbackErrorV1> {
    let recipe = if mixed { SourceReadbackRecipe::ResourceMixedProjectsV5 }
        else { SourceReadbackRecipe::ResourceSingleProjectV4 };
    sign_source_successor_from_view(readback, fresh_nonce, context, signer_generation, signing_key, recipe)
}

#[cfg(target_os = "linux")]
fn sign_source_successor_from_view(
    readback: &mut ReadOnlyProtectedJournal, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey, recipe: SourceReadbackRecipe,
) -> Result<Vec<u8>, SourceSignerReadbackErrorV1> {
    if fresh_nonce == [0; 16] || signer_generation == 0
        || recipe.is_resource() != context.approval_packet().has_resource_authorization()
    {
        return Err(SourceGenesisErrorV1::NonCanonical.into());
    }
    let names = readback.physical_names_v1();
    let journal = readback.journal_mut();
    let sequence = journal.snapshot_sequence();
    let successor = if recipe.is_single_project() {
        journal.source_first_successor_rows_v2()?
    } else {
        journal.source_project_continuation_rows_v3(Some(context.project()))?
    };
    let genesis = journal.source_tree_genesis_rows_v1()?;
    let (tree_head, lineage_head, tree_commit, generation) =
        source_first_successor_tree_readback_v2(journal, context.project())
            .map_err(SourceGenesisErrorV1::from)?;
    let original = genesis.receipts.get(&context.project()).ok_or(SourceGenesisErrorV1::Conflict)?;
    let original_ack = genesis.acks.get(&context.project()).ok_or(SourceGenesisErrorV1::Conflict)?;
    if genesis.pending.is_some()
        || (recipe.is_single_project()
            && successor.receipts.keys().any(|project| *project != context.project()))
    {
        return Err(SourceGenesisErrorV1::Conflict.into());
    }
    let receipt = successor.receipts.get(&context.project());
    let ack = successor.acks.get(&context.project());
    let phase = match (receipt, ack) {
        (None, None) => {
            if recipe.is_single_project() {
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

    let genesis_offset = 64 + context.approval_packet().as_bytes().len();
    let tail = genesis_offset + original.as_bytes().len();
    let packet_bytes = tail + 1152;
    if (!recipe.is_resource() && packet_bytes != SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2)
        || (recipe.is_resource() && !matches!(packet_bytes,
            SOURCE_RESOURCE_SUCCESSOR_LEGACY_GENESIS_BYTES_V4 | SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4))
    {
        return Err(SourceGenesisErrorV1::NonCanonical.into());
    }
    let mut packet = vec![0; packet_bytes];
    packet[..8].copy_from_slice(recipe.magic());
    packet[8..10].copy_from_slice(&recipe.version().to_be_bytes());
    packet[10] = phase as u8;
    packet[16..32].copy_from_slice(&fresh_nonce);
    packet[32..64].copy_from_slice(context.digest().as_bytes());
    packet[64..genesis_offset].copy_from_slice(context.approval_packet().as_bytes());
    packet[genesis_offset..tail].copy_from_slice(original.as_bytes());
    packet[tail..tail + 192].copy_from_slice(&original_ack.encode());
    if let Some(receipt) = receipt {
        packet[tail + 192..tail + 728].copy_from_slice(receipt.as_bytes());
    }
    if let Some(ack) = ack {
        packet[tail + 728..tail + 920].copy_from_slice(ack.as_bytes());
    }
    packet[tail + 920..tail + 968].copy_from_slice(&names.to_bytes());
    packet[tail + 968..tail + 976].copy_from_slice(&sequence.to_be_bytes());
    packet[tail + 976..tail + 984].copy_from_slice(&signer_generation.to_be_bytes());
    packet[tail + 984..tail + 1016].copy_from_slice(tree_head.as_bytes());
    packet[tail + 1016..tail + 1048].copy_from_slice(lineage_head.as_bytes());
    packet[tail + 1048..tail + 1080].copy_from_slice(tree_commit.as_bytes());
    packet[tail + 1080..tail + 1088].copy_from_slice(&generation.to_be_bytes());
    // Pure DATA shape/bindings precede real signing. Only the public verifier
    // authenticates the complete signature against the independent pinned key.
    decode_with_recipe(&packet, fresh_nonce, context, recipe, Some(original))?;
    let signature = signing_key.sign(&signature_message_with_recipe(&packet[..tail + 1088], recipe)).to_bytes();
    packet[tail + 1088..].copy_from_slice(&signature);
    if journal.snapshot_sequence() != sequence {
        return Err(SourceGenesisErrorV1::Stale.into());
    }
    Ok(packet)
}

fn decode_with_recipe<'data>(
    packet: &'data [u8], fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    recipe: SourceReadbackRecipe,
    journal_genesis: Option<&'data SourceTreeGenesisReceiptV1>,
) -> Result<ValidatedSourceReadbackFields<'data>, SourceGenesisErrorV1> {
    let permitted_length = if recipe.is_resource() {
        matches!(packet.len(), SOURCE_RESOURCE_SUCCESSOR_LEGACY_GENESIS_BYTES_V4 | SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4)
    } else {
        packet.len() == SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2
    };
    if !permitted_length
        || recipe.is_resource() != context.approval_packet().has_resource_authorization()
        || &packet[..8] != recipe.magic() || packet[8..10] != recipe.version().to_be_bytes()
        || packet[11..16] != [0; 5] || fresh_nonce == [0; 16]
        || packet[16..32] != fresh_nonce || packet[32..64] != *context.digest().as_bytes()
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let genesis_offset = 64 + context.approval_packet().as_bytes().len();
    let tail = packet.len() - 1152;
    if packet[64..genesis_offset] != *context.approval_packet().as_bytes()
        || u64_at(packet, tail + 968) == 0 || u64_at(packet, tail + 976) == 0
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let phase = match packet[10] {
        0 => SourceFirstSuccessorReadbackPhaseV2::Before,
        1 => SourceFirstSuccessorReadbackPhaseV2::Prepared,
        2 => SourceFirstSuccessorReadbackPhaseV2::Anchored,
        _ => return Err(SourceGenesisErrorV1::NonCanonical),
    };
    let genesis = match journal_genesis {
        Some(receipt) => {
            // This private signing handoff borrows only the constructor-validated
            // journal receipt copied above, never a caller's unvalidated bytes.
            if receipt.as_bytes() != &packet[genesis_offset..tail] {
                return Err(SourceGenesisErrorV1::NonCanonical);
            }
            Cow::Borrowed(receipt)
        }
        None => Cow::Owned(SourceTreeGenesisReceiptV1::decode(&packet[genesis_offset..tail])?),
    };
    let genesis_ack = crate::journal::source_tree_genesis::SourceGenesisAckV1::decode(&packet[tail..tail + 192])?;
    let names = ProtectedJournalNamesV1::from_bytes(&packet[tail + 920..tail + 968])?;
    if genesis.instance() != context.instance() || genesis.project() != context.project()
        || genesis.tree_head() != context.old_tree_head() || genesis.lineage_head() != context.old_lineage_head()
        || genesis_ack.instance != context.instance() || genesis_ack.project != context.project()
        || genesis_ack.receipt != genesis.digest() || genesis_ack.root_floor != context.predecessor_floor()
        || [tail + 984, tail + 1016, tail + 1048].into_iter().any(|offset| packet[offset..offset + 32] == [0; 32])
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let receipt = if phase == SourceFirstSuccessorReadbackPhaseV2::Before {
        if packet[tail + 192..tail + 920] != [0; 728] || names != context.source_names()
            || digest_at(packet, tail + 984) != context.old_tree_head()
            || digest_at(packet, tail + 1016) != context.old_lineage_head()
            || digest_at(packet, tail + 1048) != context.approval_packet().old_tree_commit()
            || u64_at(packet, tail + 1080) != 1
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        None
    } else {
        let receipt = SourceFirstSuccessorReceiptV2::decode(&packet[tail + 192..tail + 728])?;
        crate::hierarchy::require_first_successor_context_v2(&receipt, context)?;
        if digest_at(packet, tail + 984) != receipt.next_tree_head()
            || digest_at(packet, tail + 1016) != receipt.next_lineage_head()
            || digest_at(packet, tail + 1048) != receipt.next_tree_commit() || u64_at(packet, tail + 1080) != 2
            || (phase == SourceFirstSuccessorReadbackPhaseV2::Prepared && names != receipt.source_names())
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        Some(receipt)
    };
    let ack = if phase == SourceFirstSuccessorReadbackPhaseV2::Anchored {
        let receipt = receipt.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let ack = SourceFirstSuccessorAckV2::decode(&packet[tail + 728..tail + 920])?;
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
        if packet[tail + 728..tail + 920] != [0; 192] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        None
    };
    Ok(ValidatedSourceReadbackFields {
        bytes: packet, phase, genesis, genesis_ack_digest: genesis_ack.digest(),
        receipt, ack, names, approval: context.approval(),
    })
}

#[cfg(test)]
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
