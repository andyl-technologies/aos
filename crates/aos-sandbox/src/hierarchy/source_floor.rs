//! Inert Source hierarchy floor checkpoint, prepared intent, and recovery model.
//!
//! The fixed-width formats bind proposed Controller and Source cuts to a
//! predecessor floor.
//! They do not read a protected owner, advance an independent anchor, or mint
//! the closed Source tree append authority.
//!
//! ```text
//! AOSHSF01 | version:u16be | reserved:u16be | sequence:u64be |
//! predecessor-digest:32 | cut:336
//! AOSHFI01 | version:u16be | reserved:u16be | checkpoint:388
//!
//! cut = deployment-epoch:u64be | authority-epoch:u64be | project:16 |
//! tree-generation:u64be | tree-head:32 | lineage-head:32 |
//! source-journal-sequence:u64be | source-journal-head:32 |
//! controller-journal-sequence:u64be | controller-journal-head:32 |
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
const CUT_BYTES: usize = 336;
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
    /// Names the Controller journal position at the observed barrier cut.
    pub(crate) controller_journal_sequence: u64,
    /// Names the exact Controller journal head at that position.
    pub(crate) controller_journal_head: ObjectDigest,
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
            && self.controller_journal_sequence != 0
            && self.controller_journal_head.as_bytes() != &[0; 32]
            && self.publisher_generation != 0
            && self.publisher_head.as_bytes() != &[0; 32]
            && self.project_authorization_head.as_bytes() != &[0; 32]
            && self.seed_packet_digest.as_bytes() != &[0; 32]
            && self.seed_request_id != [0; 16]
            && self.seed_issuer_generation != 0
            && self.seed_issuer_epoch != 0
            && self.barrier_id != [0; 16]
    }

    fn encode(&self) -> [u8; CUT_BYTES] {
        let mut bytes = [0; CUT_BYTES];
        bytes[0..8].copy_from_slice(&self.deployment_epoch.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.authority_epoch.to_be_bytes());
        bytes[16..32].copy_from_slice(self.project.as_bytes());
        bytes[32..40].copy_from_slice(&self.tree_generation.to_be_bytes());
        bytes[40..72].copy_from_slice(self.tree_head.as_bytes());
        bytes[72..104].copy_from_slice(self.lineage_head.as_bytes());
        bytes[104..112].copy_from_slice(&self.source_journal_sequence.to_be_bytes());
        bytes[112..144].copy_from_slice(self.source_journal_head.as_bytes());
        bytes[144..152].copy_from_slice(&self.controller_journal_sequence.to_be_bytes());
        bytes[152..184].copy_from_slice(self.controller_journal_head.as_bytes());
        bytes[184..192].copy_from_slice(&self.publisher_generation.to_be_bytes());
        bytes[192..224].copy_from_slice(self.publisher_head.as_bytes());
        bytes[224..256].copy_from_slice(self.project_authorization_head.as_bytes());
        bytes[256..288].copy_from_slice(self.seed_packet_digest.as_bytes());
        bytes[288..304].copy_from_slice(&self.seed_request_id);
        bytes[304..312].copy_from_slice(&self.seed_issuer_generation.to_be_bytes());
        bytes[312..320].copy_from_slice(&self.seed_issuer_epoch.to_be_bytes());
        bytes[320..336].copy_from_slice(&self.barrier_id);
        bytes
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
            controller_journal_sequence: u64::from_be_bytes(take(bytes, &mut cursor)?),
            controller_journal_head: ObjectDigest::from_bytes(take(bytes, &mut cursor)?),
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
    pub(crate) fn encode(self) -> [u8; CHECKPOINT_BYTES] {
        let mut bytes = [0; CHECKPOINT_BYTES];
        bytes[0..8].copy_from_slice(CHECKPOINT_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION);
        bytes[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[20..52].copy_from_slice(
            &self
                .predecessor_digest
                .map_or([0; 32], |digest| *digest.as_bytes()),
        );
        bytes[52..].copy_from_slice(&self.cut.encode());
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
    pub(crate) fn encode(self) -> [u8; INTENT_BYTES] {
        let mut bytes = [0; INTENT_BYTES];
        bytes[0..8].copy_from_slice(INTENT_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION);
        bytes[12..].copy_from_slice(&self.checkpoint.encode());
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
/// The previous checkpoint and observed Controller-plus-Source cut must come
/// from protected, independent readback in a future caller. Even an
/// `AnchoredStructurally` result does not certify currentness, grant append
/// authority, or permit Create.
///
/// # Errors
///
/// Rejects missing intent, rollback, same-sequence fork, mismatched Controller
/// or Source heads, and a broken predecessor chain.
pub(crate) fn recover_source_hierarchy_floor_v1(
    previous: Option<&SourceHierarchyFloorCheckpointV1>,
    prepared: Option<&PreparedSourceHierarchyFloorIntentV1>,
    anchor: Option<&SourceHierarchyFloorCheckpointV1>,
    observed_cut: &SourceHierarchyFloorCutV1,
) -> Result<SourceHierarchyFloorRecoveryV1, SourceHierarchyFloorErrorV1> {
    let prepared = prepared.ok_or(SourceHierarchyFloorErrorV1::Ambiguous)?;
    let checkpoint = &prepared.checkpoint;
    let expected_sequence = previous.map_or(Some(1), |floor| floor.sequence.checked_add(1));
    let expected_predecessor = previous.map(|floor| floor.digest());
    if expected_sequence != Some(checkpoint.sequence)
        || checkpoint.predecessor_digest != expected_predecessor
        || !observed_cut.canonical()
        || checkpoint.cut != *observed_cut
        || previous.is_some_and(|floor| !continues_floor(&floor.cut, &checkpoint.cut))
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

fn continues_floor(previous: &SourceHierarchyFloorCutV1, next: &SourceHierarchyFloorCutV1) -> bool {
    let same_controller_sequence =
        previous.controller_journal_sequence == next.controller_journal_sequence;
    let controller_head_consistent = if same_controller_sequence {
        previous.controller_journal_head == next.controller_journal_head
    } else {
        previous.controller_journal_head != next.controller_journal_head
    };
    let controller_contiguous = previous.controller_journal_sequence
        <= next.controller_journal_sequence
        && controller_head_consistent;
    let controller_projection_consistent = !same_controller_sequence
        || (previous.publisher_generation == next.publisher_generation
            && previous.publisher_head == next.publisher_head
            && previous.project_authorization_head == next.project_authorization_head);

    let tree_contiguous = previous.tree_generation <= next.tree_generation
        && (previous.tree_generation != next.tree_generation
            || (previous.tree_head == next.tree_head
                && previous.lineage_head == next.lineage_head));
    let publisher_contiguous = previous.publisher_generation <= next.publisher_generation
        && (previous.publisher_generation != next.publisher_generation
            || previous.publisher_head == next.publisher_head);

    previous.project == next.project
        && previous.deployment_epoch == next.deployment_epoch
        && previous.authority_epoch < next.authority_epoch
        && previous.source_journal_sequence < next.source_journal_sequence
        && previous.source_journal_head != next.source_journal_head
        && controller_contiguous
        && controller_projection_consistent
        && tree_contiguous
        && publisher_contiguous
        && previous.seed_packet_digest == next.seed_packet_digest
        && previous.seed_request_id == next.seed_request_id
        && previous.seed_issuer_generation == next.seed_issuer_generation
        && previous.seed_issuer_epoch == next.seed_issuer_epoch
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
            controller_journal_sequence: 5,
            controller_journal_head: digest(22),
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
    fn advanced_controller_and_source_cuts_remain_structural_only() {
        let previous = SourceHierarchyFloorCheckpointV1::new(1, None, cut()).expect("first");
        let mut advanced = previous.cut;
        advanced.authority_epoch += 1;
        advanced.source_journal_sequence += 1;
        advanced.source_journal_head = digest(23);
        advanced.controller_journal_sequence += 1;
        advanced.controller_journal_head = digest(24);
        advanced.tree_generation += 1;
        advanced.tree_head = digest(25);
        advanced.lineage_head = digest(26);
        advanced.publisher_generation += 1;
        advanced.publisher_head = digest(27);
        advanced.project_authorization_head = digest(28);
        let checkpoint =
            SourceHierarchyFloorCheckpointV1::new(2, Some(previous.digest()), advanced)
                .expect("successor");
        let intent = PreparedSourceHierarchyFloorIntentV1::new(checkpoint);

        assert_eq!(
            recover_source_hierarchy_floor_v1(
                Some(&previous),
                Some(&intent),
                Some(&checkpoint),
                &advanced,
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

    #[test]
    fn successor_rejects_controller_fork_and_generation_regression() {
        let mut prior_cut = cut();
        prior_cut.tree_generation = 3;
        prior_cut.publisher_generation = 8;
        let previous = SourceHierarchyFloorCheckpointV1::new(1, None, prior_cut).expect("first");
        let mut successor_cut = prior_cut;
        successor_cut.authority_epoch += 1;
        successor_cut.source_journal_sequence += 1;
        successor_cut.source_journal_head = digest(23);

        let mut candidates = Vec::new();
        let mut controller_rollback = successor_cut;
        controller_rollback.controller_journal_sequence -= 1;
        candidates.push(controller_rollback);
        let mut controller_fork = successor_cut;
        controller_fork.controller_journal_head = digest(24);
        candidates.push(controller_fork);
        let mut unchanged_controller_head_after_advance = successor_cut;
        unchanged_controller_head_after_advance.controller_journal_sequence += 1;
        candidates.push(unchanged_controller_head_after_advance);
        let mut unchanged_source_head_after_advance = successor_cut;
        unchanged_source_head_after_advance.source_journal_head = prior_cut.source_journal_head;
        candidates.push(unchanged_source_head_after_advance);
        let mut tree_regression = successor_cut;
        tree_regression.tree_generation -= 1;
        candidates.push(tree_regression);
        let mut tree_fork = successor_cut;
        tree_fork.tree_head = digest(25);
        candidates.push(tree_fork);
        let mut publisher_regression = successor_cut;
        publisher_regression.publisher_generation -= 1;
        candidates.push(publisher_regression);
        let mut publisher_changed_without_controller_advance = successor_cut;
        publisher_changed_without_controller_advance.publisher_generation += 1;
        candidates.push(publisher_changed_without_controller_advance);
        let mut publisher_fork_without_controller_advance = successor_cut;
        publisher_fork_without_controller_advance.publisher_head = digest(29);
        candidates.push(publisher_fork_without_controller_advance);
        let mut authorization_fork = successor_cut;
        authorization_fork.project_authorization_head = digest(26);
        candidates.push(authorization_fork);
        let mut publisher_head_fork = successor_cut;
        publisher_head_fork.controller_journal_sequence += 1;
        publisher_head_fork.controller_journal_head = digest(27);
        publisher_head_fork.publisher_head = digest(28);
        candidates.push(publisher_head_fork);

        for candidate in candidates {
            let checkpoint =
                SourceHierarchyFloorCheckpointV1::new(2, Some(previous.digest()), candidate)
                    .expect("shape-valid candidate");
            let intent = PreparedSourceHierarchyFloorIntentV1::new(checkpoint);
            assert_eq!(
                recover_source_hierarchy_floor_v1(
                    Some(&previous),
                    Some(&intent),
                    Some(&checkpoint),
                    &candidate,
                ),
                Err(SourceHierarchyFloorErrorV1::Ambiguous)
            );
        }
    }
}
