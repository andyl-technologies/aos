//! Inert Source hierarchy floor checkpoint, prepared intent, and recovery model.
//!
//! The fixed-width formats bind a proposed Source cut to a predecessor floor.
//! They do not read a protected owner, advance an independent anchor, or mint
//! the closed Source tree append authority.
//!
//! ```text
//! AOSHSF01 | version:u16be | reserved:u16be | sequence:u64be |
//! predecessor-digest:32 | cut:296
//! AOSHFI01 | version:u16be | reserved:u16be | checkpoint:348
//!
//! cut = deployment-epoch:u64be | authority-epoch:u64be | project:16 |
//! tree-generation:u64be | tree-head:32 | lineage-head:32 |
//! source-journal-sequence:u64be | source-journal-head:32 |
//! publisher-generation:u64be | publisher-head:32 |
//! project-authorization-head:32 | seed-packet-digest:32 |
//! seed-request-id:16 | seed-issuer-generation:u64be |
//! seed-issuer-epoch:u64be | barrier-id:16
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const CHECKPOINT_MAGIC: &[u8; 8] = b"AOSHSF01";
const INTENT_MAGIC: &[u8; 8] = b"AOSHFI01";
const VERSION: [u8; 2] = 1_u16.to_be_bytes();
const CUT_BYTES: usize = 296;
const CHECKPOINT_BYTES: usize = 12 + 8 + 32 + CUT_BYTES;
const INTENT_BYTES: usize = 12 + CHECKPOINT_BYTES;
const CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.source-hierarchy-floor.checkpoint.v1\0";

/// Describes exact proposed heads and epochs without asserting their provenance.
///
/// A future admission owner must derive every field from held, protected
/// Controller and Source writers. A caller-supplied value is only a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceHierarchyFloorCutV1 {
    /// Selects the deployment instance owning this floor chain.
    pub(crate) deployment_epoch: u64,
    /// Selects the cross-owner authority epoch observed under the barrier.
    pub(crate) authority_epoch: u64,
    /// Names the Source project whose ancestry is checkpointed.
    pub(crate) project: ProjectId,
    /// Names the exact current Tree generation.
    pub(crate) tree_generation: u64,
    /// Names the current protected Tree record.
    pub(crate) tree_head: ObjectDigest,
    /// Names the matching immutable lineage record.
    pub(crate) lineage_head: ObjectDigest,
    /// Names the Source journal position at the observed cut.
    pub(crate) source_journal_sequence: u64,
    /// Names the exact Source journal head at that position.
    pub(crate) source_journal_head: ObjectDigest,
    /// Names the independently observed Controller publisher generation.
    pub(crate) publisher_generation: u64,
    /// Names the Controller publisher policy head.
    pub(crate) publisher_head: ObjectDigest,
    /// Names the Controller project authorization head.
    pub(crate) project_authorization_head: ObjectDigest,
    /// Commits the exact signed administrative seed packet.
    pub(crate) seed_packet_digest: ObjectDigest,
    /// Names the seed's original Controller request.
    pub(crate) seed_request_id: [u8; 16],
    /// Selects the pinned seed issuer key generation.
    pub(crate) seed_issuer_generation: u64,
    /// Names the seed issuer's monotonic epoch.
    pub(crate) seed_issuer_epoch: u64,
    /// Correlates the held Controller and Source authority cut.
    pub(crate) barrier_id: [u8; 16],
}

impl SourceHierarchyFloorCutV1 {
    fn canonical(&self) -> bool {
        self.deployment_epoch != 0
            && self.authority_epoch != 0
            && self.project.as_bytes() != &[0; 16]
            && self.tree_generation != 0
            && self.tree_generation != u64::MAX
            && self.tree_head.as_bytes() != &[0; 32]
            && self.lineage_head.as_bytes() != &[0; 32]
            && self.source_journal_sequence != 0
            && self.source_journal_head.as_bytes() != &[0; 32]
            && self.publisher_generation != 0
            && self.publisher_head.as_bytes() != &[0; 32]
            && self.project_authorization_head.as_bytes() != &[0; 32]
            && self.seed_packet_digest.as_bytes() != &[0; 32]
            && self.seed_request_id != [0; 16]
            && self.seed_issuer_generation != 0
            && self.seed_issuer_epoch != 0
            && self.barrier_id != [0; 16]
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.deployment_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.authority_epoch.to_be_bytes());
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(&self.tree_generation.to_be_bytes());
        bytes.extend_from_slice(self.tree_head.as_bytes());
        bytes.extend_from_slice(self.lineage_head.as_bytes());
        bytes.extend_from_slice(&self.source_journal_sequence.to_be_bytes());
        bytes.extend_from_slice(self.source_journal_head.as_bytes());
        bytes.extend_from_slice(&self.publisher_generation.to_be_bytes());
        bytes.extend_from_slice(self.publisher_head.as_bytes());
        bytes.extend_from_slice(self.project_authorization_head.as_bytes());
        bytes.extend_from_slice(self.seed_packet_digest.as_bytes());
        bytes.extend_from_slice(&self.seed_request_id);
        bytes.extend_from_slice(&self.seed_issuer_generation.to_be_bytes());
        bytes.extend_from_slice(&self.seed_issuer_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.barrier_id);
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CUT_BYTES {
            return None;
        }
        let mut cursor = 0;
        let cut = Self {
            deployment_epoch: u64::from_be_bytes(take(bytes, &mut cursor)?),
            authority_epoch: u64::from_be_bytes(take(bytes, &mut cursor)?),
            project: ProjectId::from_bytes(take(bytes, &mut cursor)?),
            tree_generation: u64::from_be_bytes(take(bytes, &mut cursor)?),
            tree_head: ObjectDigest::from_bytes(take(bytes, &mut cursor)?),
            lineage_head: ObjectDigest::from_bytes(take(bytes, &mut cursor)?),
            source_journal_sequence: u64::from_be_bytes(take(bytes, &mut cursor)?),
            source_journal_head: ObjectDigest::from_bytes(take(bytes, &mut cursor)?),
            publisher_generation: u64::from_be_bytes(take(bytes, &mut cursor)?),
            publisher_head: ObjectDigest::from_bytes(take(bytes, &mut cursor)?),
            project_authorization_head: ObjectDigest::from_bytes(take(bytes, &mut cursor)?),
            seed_packet_digest: ObjectDigest::from_bytes(take(bytes, &mut cursor)?),
            seed_request_id: take(bytes, &mut cursor)?,
            seed_issuer_generation: u64::from_be_bytes(take(bytes, &mut cursor)?),
            seed_issuer_epoch: u64::from_be_bytes(take(bytes, &mut cursor)?),
            barrier_id: take(bytes, &mut cursor)?,
        };
        (cursor == bytes.len() && cut.canonical()).then_some(cut)
    }
}

/// Retains one proposed independent ancestry floor without installing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceHierarchyFloorCheckpointV1 {
    sequence: u64,
    predecessor_digest: Option<ObjectDigest>,
    cut: SourceHierarchyFloorCutV1,
}

impl SourceHierarchyFloorCheckpointV1 {
    /// Constructs a canonical checkpoint with an exact predecessor digest.
    ///
    /// # Errors
    ///
    /// Rejects zero or exhausted sequence, sentinel fields, and an absent
    /// predecessor outside the first sequence.
    pub(crate) fn new(
        sequence: u64,
        predecessor_digest: Option<ObjectDigest>,
        cut: SourceHierarchyFloorCutV1,
    ) -> Result<Self, SourceHierarchyFloorErrorV1> {
        if sequence == 0
            || sequence == u64::MAX
            || predecessor_digest.is_none() != (sequence == 1)
            || predecessor_digest.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || !cut.canonical()
        {
            return Err(SourceHierarchyFloorErrorV1::NonCanonical);
        }
        Ok(Self {
            sequence,
            predecessor_digest,
            cut,
        })
    }

    /// Encodes the exact, fixed-width checkpoint bytes.
    #[must_use]
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CHECKPOINT_BYTES);
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&VERSION);
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .predecessor_digest
                .map_or([0; 32], |digest| *digest.as_bytes()),
        );
        self.cut.encode(&mut bytes);
        bytes
    }

    /// Returns the domain-separated digest of the canonical checkpoint bytes.
    #[must_use]
    pub(crate) fn digest(self) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(CHECKPOINT_DIGEST_DOMAIN);
        digest.update(self.encode());
        ObjectDigest::from_bytes(digest.finalize().into())
    }
}

/// Decodes only the canonical first-version checkpoint encoding.
pub(crate) fn decode_source_hierarchy_floor_checkpoint_v1(
    bytes: &[u8],
) -> Option<SourceHierarchyFloorCheckpointV1> {
    if bytes.len() != CHECKPOINT_BYTES
        || &bytes[..8] != CHECKPOINT_MAGIC
        || bytes[8..10] != VERSION
        || bytes[10..12] != [0; 2]
    {
        return None;
    }
    let sequence = u64::from_be_bytes(bytes[12..20].try_into().ok()?);
    let predecessor_bytes: [u8; 32] = bytes[20..52].try_into().ok()?;
    let predecessor_digest =
        (predecessor_bytes != [0; 32]).then_some(ObjectDigest::from_bytes(predecessor_bytes));
    let cut = SourceHierarchyFloorCutV1::decode(&bytes[52..])?;
    SourceHierarchyFloorCheckpointV1::new(sequence, predecessor_digest, cut).ok()
}

/// Retains the entire proposed checkpoint before an independent anchor update.
///
/// Intent custody is required on both sides of the anchor update. Its presence
/// is not proof that the Controller and Source cuts were independently checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedSourceHierarchyFloorIntentV1 {
    checkpoint: SourceHierarchyFloorCheckpointV1,
}

impl PreparedSourceHierarchyFloorIntentV1 {
    /// Wraps the exact checkpoint proposed for an anchor compare-and-swap.
    #[must_use]
    pub(crate) const fn new(checkpoint: SourceHierarchyFloorCheckpointV1) -> Self {
        Self { checkpoint }
    }

    /// Encodes the fixed-width prepared intent.
    #[must_use]
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(INTENT_BYTES);
        bytes.extend_from_slice(INTENT_MAGIC);
        bytes.extend_from_slice(&VERSION);
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.checkpoint.encode());
        bytes
    }
}

/// Decodes an intent only when its nested checkpoint is canonical.
pub(crate) fn decode_prepared_source_hierarchy_floor_intent_v1(
    bytes: &[u8],
) -> Option<PreparedSourceHierarchyFloorIntentV1> {
    if bytes.len() != INTENT_BYTES
        || &bytes[..8] != INTENT_MAGIC
        || bytes[8..10] != VERSION
        || bytes[10..12] != [0; 2]
    {
        return None;
    }
    Some(PreparedSourceHierarchyFloorIntentV1::new(
        decode_source_hierarchy_floor_checkpoint_v1(&bytes[12..])?,
    ))
}

/// Classifies only the local relationship of a prepared intent and anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceHierarchyFloorRecoveryV1 {
    /// The Source cut is present, but the proposed checkpoint is not anchored.
    PreparedUnanchored,
    /// The exact proposed checkpoint is anchored and structurally replayable.
    AnchoredStructurally,
}

/// Rejects noncanonical or ambiguous floor history.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub(crate) enum SourceHierarchyFloorErrorV1 {
    /// A record has invalid framing, sentinel fields, or sequence shape.
    #[error("noncanonical Source hierarchy floor")]
    NonCanonical,
    /// An intent, Source cut, predecessor, or anchor is absent or inconsistent.
    #[error("Source hierarchy floor recovery is ambiguous")]
    Ambiguous,
}

/// Reduces the crash cut around an independent anchor update without effects.
///
/// The previous checkpoint and observed Source cut must come from protected,
/// independent readback in a future caller. Even `AnchoredStructurally` does
/// not certify currentness, grant append authority, or permit Create.
///
/// # Errors
///
/// Rejects missing intent, rollback, same-sequence fork, mismatched Source
/// heads, and a broken predecessor chain.
pub(crate) fn recover_source_hierarchy_floor_v1(
    previous: Option<&SourceHierarchyFloorCheckpointV1>,
    prepared: Option<&PreparedSourceHierarchyFloorIntentV1>,
    anchor: Option<&SourceHierarchyFloorCheckpointV1>,
    observed_source: &SourceHierarchyFloorCutV1,
) -> Result<SourceHierarchyFloorRecoveryV1, SourceHierarchyFloorErrorV1> {
    let prepared = prepared.ok_or(SourceHierarchyFloorErrorV1::Ambiguous)?;
    let checkpoint = &prepared.checkpoint;
    let expected_sequence = previous.map_or(Some(1), |floor| floor.sequence.checked_add(1));
    let expected_predecessor = previous.map(|floor| floor.digest());
    if expected_sequence != Some(checkpoint.sequence)
        || checkpoint.predecessor_digest != expected_predecessor
        || !observed_source.canonical()
        || checkpoint.cut != *observed_source
        || previous.is_some_and(|floor| {
            floor.cut.project != checkpoint.cut.project
                || floor.cut.deployment_epoch != checkpoint.cut.deployment_epoch
                || floor.cut.authority_epoch >= checkpoint.cut.authority_epoch
                || floor.cut.source_journal_sequence >= checkpoint.cut.source_journal_sequence
                || floor.cut.seed_packet_digest != checkpoint.cut.seed_packet_digest
                || floor.cut.seed_request_id != checkpoint.cut.seed_request_id
                || floor.cut.seed_issuer_generation != checkpoint.cut.seed_issuer_generation
                || floor.cut.seed_issuer_epoch != checkpoint.cut.seed_issuer_epoch
        })
    {
        return Err(SourceHierarchyFloorErrorV1::Ambiguous);
    }

    match anchor {
        Some(anchored) if anchored == checkpoint => {
            Ok(SourceHierarchyFloorRecoveryV1::AnchoredStructurally)
        }
        Some(anchored) if previous == Some(anchored) => {
            Ok(SourceHierarchyFloorRecoveryV1::PreparedUnanchored)
        }
        None if previous.is_none() => Ok(SourceHierarchyFloorRecoveryV1::PreparedUnanchored),
        _ => Err(SourceHierarchyFloorErrorV1::Ambiguous),
    }
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<[u8; N]> {
    let end = cursor.checked_add(N)?;
    let value = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn cut() -> SourceHierarchyFloorCutV1 {
        SourceHierarchyFloorCutV1 {
            deployment_epoch: 7,
            authority_epoch: 11,
            project: ProjectId::from_bytes([1; 16]),
            tree_generation: 1,
            tree_head: digest(2),
            lineage_head: digest(3),
            source_journal_sequence: 4,
            source_journal_head: digest(5),
            publisher_generation: 6,
            publisher_head: digest(7),
            project_authorization_head: digest(8),
            seed_packet_digest: digest(9),
            seed_request_id: [10; 16],
            seed_issuer_generation: 12,
            seed_issuer_epoch: 13,
            barrier_id: [14; 16],
        }
    }

    fn next(previous: SourceHierarchyFloorCheckpointV1) -> SourceHierarchyFloorCheckpointV1 {
        let mut successor = cut();
        successor.authority_epoch += 1;
        successor.source_journal_sequence += 1;
        successor.tree_generation += 1;
        successor.tree_head = digest(15);
        successor.lineage_head = digest(16);
        successor.source_journal_head = digest(17);
        SourceHierarchyFloorCheckpointV1::new(2, Some(previous.digest()), successor)
            .expect("successor")
    }

    #[test]
    fn checkpoint_and_intent_have_one_canonical_encoding() {
        let checkpoint = SourceHierarchyFloorCheckpointV1::new(1, None, cut()).expect("first");
        let intent = PreparedSourceHierarchyFloorIntentV1::new(checkpoint);
        assert_eq!(
            decode_source_hierarchy_floor_checkpoint_v1(&checkpoint.encode()),
            Some(checkpoint)
        );
        assert_eq!(
            decode_prepared_source_hierarchy_floor_intent_v1(&intent.encode()),
            Some(intent)
        );

        let mut malformed = checkpoint.encode();
        malformed[10] = 1;
        assert!(decode_source_hierarchy_floor_checkpoint_v1(&malformed).is_none());
        malformed = checkpoint.encode();
        malformed[52..60].fill(0);
        assert!(decode_source_hierarchy_floor_checkpoint_v1(&malformed).is_none());
    }

    #[test]
    fn crash_before_and_after_anchor_update_remain_distinct() {
        let previous = SourceHierarchyFloorCheckpointV1::new(1, None, cut()).expect("first");
        let checkpoint = next(previous);
        let intent = PreparedSourceHierarchyFloorIntentV1::new(checkpoint);

        assert_eq!(
            recover_source_hierarchy_floor_v1(
                Some(&previous),
                Some(&intent),
                Some(&previous),
                &checkpoint.cut,
            ),
            Ok(SourceHierarchyFloorRecoveryV1::PreparedUnanchored)
        );
        assert_eq!(
            recover_source_hierarchy_floor_v1(
                Some(&previous),
                Some(&intent),
                Some(&checkpoint),
                &checkpoint.cut,
            ),
            Ok(SourceHierarchyFloorRecoveryV1::AnchoredStructurally)
        );
    }

    #[test]
    fn rollback_fork_and_missing_intent_fail_closed() {
        let previous = SourceHierarchyFloorCheckpointV1::new(1, None, cut()).expect("first");
        let checkpoint = next(previous);
        let intent = PreparedSourceHierarchyFloorIntentV1::new(checkpoint);
        let mut forked_cut = checkpoint.cut;
        forked_cut.tree_head = digest(21);
        let fork = SourceHierarchyFloorCheckpointV1::new(
            checkpoint.sequence,
            checkpoint.predecessor_digest,
            forked_cut,
        )
        .expect("fork");

        assert_eq!(
            recover_source_hierarchy_floor_v1(
                Some(&previous),
                Some(&intent),
                Some(&checkpoint),
                &previous.cut,
            ),
            Err(SourceHierarchyFloorErrorV1::Ambiguous)
        );
        assert_eq!(
            recover_source_hierarchy_floor_v1(
                Some(&previous),
                Some(&intent),
                Some(&fork),
                &checkpoint.cut,
            ),
            Err(SourceHierarchyFloorErrorV1::Ambiguous)
        );
        assert_eq!(
            recover_source_hierarchy_floor_v1(
                Some(&previous),
                None,
                Some(&checkpoint),
                &checkpoint.cut,
            ),
            Err(SourceHierarchyFloorErrorV1::Ambiguous)
        );
    }
}
