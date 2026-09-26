//! Closed, structural Source Tree lineage retained in the protected journal.
//!
//! ```text
//! AOSHTL01 | version:u16be | reserved:u16be | project:16 |
//! generation:u64be | prior-tree-head:32 | tree-head:32 |
//! prior-lineage-head:32 | tree-commitment:32 | seed-length:u16be |
//! reserved:u16be | initial AOSCSE01 packet:0-or-224
//! ```
//!
//! This is not a Controller receipt or a rollback-resistant floor. Old Tree
//! bodies are overwritten by the materialized journal: replay checks their
//! exact committed heads and contiguous links, but cannot revalidate old body
//! contents after overwrite. The current Tree body is always revalidated.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, ProjectId, Revision};

use crate::journal::Journal;
use crate::lifecycle::protected_journal_adapter::decode_reducer_payload_with_validator;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::codec::{decode_tree_v1, tree_commitment_v1};
use super::graph::SandboxTreeV1;
use super::model::TreeLimitsV1;
use super::protected_journal::{
    HierarchyJournalCommitOutcomeV1, HierarchyJournalReplayPhaseV1,
    HierarchyProtectedJournalErrorV1, HierarchyProtectedJournalKeyV1,
    HierarchyProtectedJournalProjectionV1, HierarchyProtectedJournalSchemaV1,
    HierarchyProtectedJournalV1, HierarchyProtectedRecordKindV1,
    HierarchyProtectedReplayValidatorV1, HierarchyReducerRecordV1,
    claim_hierarchy_protected_journal_v1, hierarchy_reducer_envelope_v1,
    recover_hierarchy_replay_validator_for_closed_lineage_v1,
};
use super::source_seed::{CONTROLLER_SOURCE_TREE_SEED_BYTES_V1, ControllerSourceTreeSeedV1};

const MAGIC: &[u8; 8] = b"AOSHTL01";
const HEADER_BYTES: usize = 168;

/// Retains one immutable Tree generation link, without granting its authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClosedTreeLineageRecordV1 {
    project: ProjectId,
    generation: u64,
    prior_tree_head: Option<ObjectDigest>,
    tree_head: ObjectDigest,
    prior_lineage_head: Option<ObjectDigest>,
    tree_commitment: ObjectDigest,
    initial_seed_packet: Option<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1]>,
}

impl ClosedTreeLineageRecordV1 {
    fn new(
        project: ProjectId,
        generation: u64,
        prior_tree_head: Option<ObjectDigest>,
        tree_head: ObjectDigest,
        prior_lineage_head: Option<ObjectDigest>,
        tree_commitment: ObjectDigest,
        initial_seed_packet: Option<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1]>,
    ) -> Option<Self> {
        let genesis = generation == 1;
        if project.as_bytes() == &[0; 16]
            || generation == 0
            || generation == u64::MAX
            || tree_head.as_bytes() == &[0; 32]
            || tree_commitment.as_bytes() == &[0; 32]
            || prior_tree_head.is_none() != genesis
            || prior_lineage_head.is_none() != genesis
            || initial_seed_packet.is_none() != genesis
            || prior_tree_head.is_some_and(|head| head.as_bytes() == &[0; 32])
            || prior_lineage_head.is_some_and(|head| head.as_bytes() == &[0; 32])
            || initial_seed_packet.as_ref().is_some_and(|packet| {
                seed_claims(packet).is_none_or(|seed| seed.project() != project)
            })
        {
            return None;
        }
        Some(Self {
            project,
            generation,
            prior_tree_head,
            tree_head,
            prior_lineage_head,
            tree_commitment,
            initial_seed_packet,
        })
    }

    pub(super) fn identity(&self) -> [u8; 48] {
        let mut identity = [0; 48];
        identity[..16].copy_from_slice(self.project.as_bytes());
        identity[24..32].copy_from_slice(&self.generation.to_be_bytes());
        identity[32..48].copy_from_slice(self.project.as_bytes());
        identity
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            HEADER_BYTES
                + self
                    .initial_seed_packet
                    .as_ref()
                    .map_or(0, |seed| seed.len()),
        );
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .prior_tree_head
                .map_or([0; 32], |head| *head.as_bytes()),
        );
        bytes.extend_from_slice(self.tree_head.as_bytes());
        bytes.extend_from_slice(
            &self
                .prior_lineage_head
                .map_or([0; 32], |head| *head.as_bytes()),
        );
        bytes.extend_from_slice(self.tree_commitment.as_bytes());
        let seed = self
            .initial_seed_packet
            .as_ref()
            .map_or(&[][..], |packet| packet.as_slice());
        bytes.extend_from_slice(&(seed.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(seed);
        bytes
    }
}

pub(crate) fn decode_closed_tree_lineage_v1(bytes: &[u8]) -> Option<ClosedTreeLineageRecordV1> {
    if bytes.len() < HEADER_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..12] != [0; 2]
        || bytes[166..168] != [0; 2]
    {
        return None;
    }
    let seed_len = usize::from(u16::from_be_bytes(bytes[164..166].try_into().ok()?));
    if bytes.len() != HEADER_BYTES + seed_len
        || (seed_len != 0 && seed_len != CONTROLLER_SOURCE_TREE_SEED_BYTES_V1)
    {
        return None;
    }
    let initial_seed_packet = (seed_len != 0)
        .then(|| bytes[HEADER_BYTES..].try_into().ok())
        .flatten();
    let record = ClosedTreeLineageRecordV1::new(
        ProjectId::from_bytes(bytes[12..28].try_into().ok()?),
        u64::from_be_bytes(bytes[28..36].try_into().ok()?),
        optional_head(bytes[36..68].try_into().ok()?),
        ObjectDigest::from_bytes(bytes[68..100].try_into().ok()?),
        optional_head(bytes[100..132].try_into().ok()?),
        ObjectDigest::from_bytes(bytes[132..164].try_into().ok()?),
        initial_seed_packet,
    )?;
    (record.encode() == bytes).then_some(record)
}

fn optional_head(bytes: [u8; 32]) -> Option<ObjectDigest> {
    (bytes != [0; 32]).then_some(ObjectDigest::from_bytes(bytes))
}

// Shape-checks a retained proposal. This does not authenticate its signature,
// Controller current heads, or anti-replay epoch.
fn seed_claims(
    packet: &[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
) -> Option<ControllerSourceTreeSeedV1> {
    if &packet[..8] != b"AOSCSE01"
        || packet[8..10] != 1_u16.to_be_bytes()
        || packet[10..12] != [0; 2]
    {
        return None;
    }
    let issuer_generation = u64::from_be_bytes(packet[12..20].try_into().ok()?);
    if issuer_generation == 0 {
        return None;
    }
    let mut limits = [0_usize; 7];
    for (index, limit) in limits.iter_mut().enumerate() {
        let offset = 132 + index * 4;
        *limit = usize::try_from(u32::from_be_bytes(
            packet[offset..offset + 4].try_into().ok()?,
        ))
        .ok()?;
    }
    let limits = TreeLimitsV1::new(
        limits[0], limits[1], limits[2], limits[3], limits[4], limits[5], limits[6],
    )
    .ok()?;
    let seed = ControllerSourceTreeSeedV1::new(
        ProjectId::from_bytes(packet[20..36].try_into().ok()?),
        limits,
        u64::from_be_bytes(packet[36..44].try_into().ok()?),
        ObjectDigest::from_bytes(packet[44..76].try_into().ok()?),
        ObjectDigest::from_bytes(packet[76..108].try_into().ok()?),
        packet[108..124].try_into().ok()?,
        u64::from_be_bytes(packet[124..132].try_into().ok()?),
    )
    .ok()?;
    Some(seed)
}

/// A structurally replayed current Tree and its immutable link head.
pub(super) struct ClosedTreeLineageHeadV1 {
    pub(super) tree: SandboxTreeV1,
    pub(super) tree_head: ObjectDigest,
    pub(super) lineage_head: ObjectDigest,
}

/// Replays local structure only; it never certifies Source currentness.
pub(super) fn replay_closed_tree_lineage_v1(
    journal: &mut Journal,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(journal)?;
    let claimed = claim_hierarchy_protected_journal_v1(journal, validator.clone())?;
    let projection = claimed.replay()?;
    verify_closed_tree_lineage_projection_v1(&projection, &validator)
}

fn verify_closed_tree_lineage_projection_v1(
    projection: &HierarchyProtectedJournalProjectionV1,
    validator: &super::protected_journal::HierarchyProtectedReplayValidatorV1,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    let invalid = || HierarchyProtectedJournalErrorV1::NonCanonicalRecord;
    let mut trees = BTreeMap::new();
    let mut links: BTreeMap<ProjectId, Vec<(ClosedTreeLineageRecordV1, ObjectDigest)>> =
        BTreeMap::new();

    for record in projection.records() {
        let kind = record.key().kind();
        if !matches!(
            kind,
            HierarchyProtectedRecordKindV1::Tree | HierarchyProtectedRecordKindV1::TreeLineage
        ) {
            continue;
        }
        let payload = decode_reducer_payload_with_validator::<HierarchyProtectedJournalSchemaV1>(
            record.key(),
            record.payload(),
            validator,
        )?;
        match kind {
            HierarchyProtectedRecordKindV1::Tree => {
                let tree = decode_tree_v1(payload.body()).map_err(|_| invalid())?;
                if record.revision() != tree.tree_generation().get()
                    || trees.insert(tree.project(), (tree, record)).is_some()
                {
                    return Err(invalid());
                }
            }
            HierarchyProtectedRecordKindV1::TreeLineage => {
                let link = decode_closed_tree_lineage_v1(payload.body()).ok_or_else(invalid)?;
                if record.revision() != 1 || record.predecessor().is_some() {
                    return Err(invalid());
                }
                links
                    .entry(link.project)
                    .or_default()
                    .push((link, record.digest()));
            }
            _ => return Err(invalid()),
        }
    }

    let paired_heads = projection
        .transactions()
        .iter()
        .filter(|transaction| {
            transaction.phase() == HierarchyJournalReplayPhaseV1::Observed
                && transaction.records().len() == 2
                && transaction.records()[0].key().kind() == HierarchyProtectedRecordKindV1::Tree
                && transaction.records()[1].key().kind()
                    == HierarchyProtectedRecordKindV1::TreeLineage
        })
        .map(|transaction| {
            (
                transaction.records()[0].digest(),
                transaction.records()[1].digest(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut current = BTreeMap::new();
    for (project, (tree, record)) in trees {
        let mut project_links = links.remove(&project).ok_or_else(invalid)?;
        project_links.sort_by_key(|(link, _)| link.generation);
        if project_links.len() as u64 != tree.tree_generation().get() {
            return Err(invalid());
        }
        let mut prior_tree_head = None;
        let mut prior_lineage_head = None;
        let mut initial_limits = None;
        for (index, (link, lineage_head)) in project_links.iter().enumerate() {
            if link.generation != index as u64 + 1
                || link.prior_tree_head != prior_tree_head
                || link.prior_lineage_head != prior_lineage_head
            {
                return Err(invalid());
            }
            if let Some(packet) = &link.initial_seed_packet {
                initial_limits = Some(seed_claims(packet).ok_or_else(invalid)?.limits());
            }
            prior_tree_head = Some(link.tree_head);
            prior_lineage_head = Some(*lineage_head);
        }
        let (last, lineage_head) = project_links.last().ok_or_else(invalid)?;
        if last.tree_head != record.digest()
            || last.prior_tree_head != record.predecessor()
            || last.tree_commitment != tree_commitment_v1(&tree).map_err(|_| invalid())?
            || initial_limits != Some(tree.limits())
            || (tree.tree_generation().get() == 1
                && (tree.records().next().is_some() || tree.tombstones().next().is_some()))
        {
            return Err(invalid());
        }
        if paired_heads.get(&record.digest()) != Some(lineage_head) {
            return Err(invalid());
        }
        current.insert(
            project,
            ClosedTreeLineageHeadV1 {
                tree,
                tree_head: record.digest(),
                lineage_head: *lineage_head,
            },
        );
    }
    if !links.is_empty() {
        return Err(invalid());
    }
    Ok(current)
}

/// Names authority that the current repository deliberately cannot mint.
///
/// A future admission path must construct this only while it retains the
/// Controller writer and an independent epoch floor across the Source commit.
pub(super) struct ClosedSourceTreeAppendAuthorityV1 {
    _private: (),
}

/// Holds the Source writer for an atomic Tree-plus-lineage append.
pub(super) struct ClosedSourceTreeLineageWriterV1<'owner> {
    journal: HierarchyProtectedJournalV1<'owner>,
    validator: HierarchyProtectedReplayValidatorV1,
    _authority: &'owner ClosedSourceTreeAppendAuthorityV1,
}

impl<'owner> ClosedSourceTreeLineageWriterV1<'owner> {
    /// Checks the fixed named Source writer before structural replay.
    ///
    /// This cannot be called in production until the independent admission
    /// authority has a real constructor. Local replay is never that authority.
    pub(super) fn claim(
        source: &'owner mut ProtectedSourceDomainJournalOwnerV1,
        authority: &'owner ClosedSourceTreeAppendAuthorityV1,
    ) -> Result<Self, HierarchyProtectedJournalErrorV1> {
        source.require_fixed_named_writer_v1()?;
        Self::claim_journal(source.journal(), authority)
    }

    fn claim_journal(
        journal: &'owner mut Journal,
        authority: &'owner ClosedSourceTreeAppendAuthorityV1,
    ) -> Result<Self, HierarchyProtectedJournalErrorV1> {
        let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(journal)?;
        let claimed = claim_hierarchy_protected_journal_v1(journal, validator.clone())?;
        verify_closed_tree_lineage_projection_v1(&claimed.replay()?, &validator)?;
        Ok(Self {
            journal: claimed,
            validator,
            _authority: authority,
        })
    }

    #[cfg(test)]
    fn claim_for_test(
        source: &'owner mut ProtectedSourceDomainJournalOwnerV1,
        authority: &'owner ClosedSourceTreeAppendAuthorityV1,
    ) -> Result<Self, HierarchyProtectedJournalErrorV1> {
        Self::claim_journal(source.journal(), authority)
    }

    /// Appends an empty initial Tree and its exact seed-bearing link together.
    ///
    /// The packet shape is checked, but its signature and Controller claims
    /// are not authenticated here. The unavailable admission token must carry
    /// those checks before production can call this method.
    pub(super) fn append_genesis(
        &mut self,
        packet: [u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
    ) -> Result<HierarchyJournalCommitOutcomeV1, HierarchyProtectedJournalErrorV1> {
        let seed =
            seed_claims(&packet).ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        if self.current()?.contains_key(&seed.project()) {
            return Err(HierarchyProtectedJournalErrorV1::CompareAndSwapFailed);
        }
        let tree = SandboxTreeV1::from_records(
            seed.project(),
            Revision::new(1),
            seed.limits(),
            Vec::new(),
        )
        .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        self.append_pair(&tree, None, None, Some(packet), seed.request_id())
    }

    /// Appends exactly one successor generation and its immutable link.
    ///
    /// This only proves local structure. Future admission must separately
    /// validate the requested transition under held cross-owner authority.
    pub(super) fn append_transition(
        &mut self,
        tree: &SandboxTreeV1,
        transaction_id: [u8; 16],
    ) -> Result<HierarchyJournalCommitOutcomeV1, HierarchyProtectedJournalErrorV1> {
        let current = self.current()?;
        let previous = current
            .get(&tree.project())
            .ok_or(HierarchyProtectedJournalErrorV1::CompareAndSwapFailed)?;
        if previous.tree.limits() != tree.limits()
            || previous.tree.tree_generation().get().checked_add(1)
                != Some(tree.tree_generation().get())
        {
            return Err(HierarchyProtectedJournalErrorV1::CompareAndSwapFailed);
        }
        self.append_pair(
            tree,
            Some(previous.tree_head),
            Some(previous.lineage_head),
            None,
            transaction_id,
        )
    }

    fn current(
        &self,
    ) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1>
    {
        verify_closed_tree_lineage_projection_v1(&self.journal.replay()?, &self.validator)
    }

    fn append_pair(
        &mut self,
        tree: &SandboxTreeV1,
        prior_tree_head: Option<ObjectDigest>,
        prior_lineage_head: Option<ObjectDigest>,
        initial_seed_packet: Option<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1]>,
        transaction_id: [u8; 16],
    ) -> Result<HierarchyJournalCommitOutcomeV1, HierarchyProtectedJournalErrorV1> {
        let tree_key = tree_key(tree.project())?;
        let tree_envelope = hierarchy_reducer_envelope_v1(
            tree_key,
            tree.tree_generation().get(),
            prior_tree_head,
            HierarchyReducerRecordV1::Tree(tree),
            &self.validator,
        )?;
        let commitment = tree_commitment_v1(tree)
            .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let link = ClosedTreeLineageRecordV1::new(
            tree.project(),
            tree.tree_generation().get(),
            prior_tree_head,
            tree_envelope.digest(),
            prior_lineage_head,
            commitment,
            initial_seed_packet,
        )
        .ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let lineage_envelope = hierarchy_reducer_envelope_v1(
            HierarchyProtectedJournalKeyV1::new(
                HierarchyProtectedRecordKindV1::TreeLineage,
                link.identity().to_vec(),
            )?,
            1,
            None,
            HierarchyReducerRecordV1::TreeLineage(&link),
            &self.validator,
        )?;
        let prepared = self
            .journal
            .plan(transaction_id, vec![tree_envelope, lineage_envelope])?;
        self.journal.commit(prepared)
    }
}

fn tree_key(
    project: ProjectId,
) -> Result<HierarchyProtectedJournalKeyV1, HierarchyProtectedJournalErrorV1> {
    let mut identity = Vec::with_capacity(48);
    for _ in 0..3 {
        identity.extend_from_slice(project.as_bytes());
    }
    HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, identity)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_core::ObjectDigest;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::JournalLimits;
    use crate::hierarchy::source_seed::sign_controller_source_tree_seed_v1;
    use crate::journal::Journal;
    use crate::lifecycle::protected_journal_adapter::DomainCommitOutcomeV1;

    fn fixture() -> (tempfile::TempDir, ProtectedSourceDomainJournalOwnerV1) {
        let directory = tempfile::tempdir().expect("private directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let uid = fs::metadata(directory.path()).expect("metadata").uid();
        let journal = Journal::open_protected_at_uid(
            directory.path(),
            "source-domains.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("protected journal")
        .0;
        (
            directory,
            ProtectedSourceDomainJournalOwnerV1::from_test_journal(journal),
        )
    }

    fn packet(project: ProjectId) -> [u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1] {
        let seed = ControllerSourceTreeSeedV1::new(
            project,
            limits(),
            5,
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            [4; 16],
            9,
        )
        .expect("seed proposal");
        sign_controller_source_tree_seed_v1(seed, 7, &SigningKey::from_bytes(&[41; 32]))
            .expect("packet")
    }

    fn test_authority() -> ClosedSourceTreeAppendAuthorityV1 {
        ClosedSourceTreeAppendAuthorityV1 { _private: () }
    }

    fn limits() -> TreeLimitsV1 {
        TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).expect("limits")
    }

    fn empty_tree(project: ProjectId, generation: u64) -> SandboxTreeV1 {
        SandboxTreeV1::from_records(project, Revision::new(generation), limits(), Vec::new())
            .expect("tree")
    }

    fn commit_tree_only(
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        tree: &SandboxTreeV1,
        predecessor: Option<ObjectDigest>,
        transaction_id: [u8; 16],
    ) {
        let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(source.journal())
            .expect("validator");
        let mut journal = claim_hierarchy_protected_journal_v1(source.journal(), validator.clone())
            .expect("claim");
        let envelope = hierarchy_reducer_envelope_v1(
            tree_key(tree.project()).expect("tree key"),
            tree.tree_generation().get(),
            predecessor,
            HierarchyReducerRecordV1::Tree(tree),
            &validator,
        )
        .expect("tree envelope");
        let plan = journal.plan(transaction_id, vec![envelope]).expect("plan");
        assert!(matches!(
            journal.commit(plan).expect("commit"),
            DomainCommitOutcomeV1::Applied(_)
        ));
    }

    #[test]
    fn no_tree_projects_remain_absent() {
        let (_directory, mut source) = fixture();
        assert!(
            replay_closed_tree_lineage_v1(source.journal())
                .expect("replay")
                .is_empty()
        );
    }

    #[test]
    fn atomic_genesis_and_transition_retain_exact_contiguous_heads() {
        let (_directory, mut source) = fixture();
        let authority = test_authority();
        let project = ProjectId::from_bytes([1; 16]);
        let seed_packet = packet(project);

        {
            let mut writer =
                ClosedSourceTreeLineageWriterV1::claim_for_test(&mut source, &authority)
                    .expect("closed writer");
            assert!(matches!(
                writer.append_genesis(seed_packet).expect("genesis"),
                DomainCommitOutcomeV1::Applied(_)
            ));
            let successor = empty_tree(project, 2);
            assert!(matches!(
                writer
                    .append_transition(&successor, [5; 16])
                    .expect("transition"),
                DomainCommitOutcomeV1::Applied(_)
            ));
        }

        let heads = replay_closed_tree_lineage_v1(source.journal()).expect("closed replay");
        assert_eq!(
            heads.get(&project).expect("project").tree.tree_generation(),
            Revision::new(2)
        );
        assert!(
            super::super::protected_journal::replay_project_ancestry_head_v1(
                source.journal(),
                project,
            )
            .is_err()
        );
        assert!(
            super::super::protected_journal::HierarchyProtectedJournalOwnerV1::claim(&mut source)
                .is_err()
        );
    }

    #[test]
    fn tree_without_matching_lineage_fails_cold_replay() {
        let (_directory, mut source) = fixture();
        let project = ProjectId::from_bytes([1; 16]);
        commit_tree_only(&mut source, &empty_tree(project, 1), None, [6; 16]);

        assert!(replay_closed_tree_lineage_v1(source.journal()).is_err());
    }

    #[test]
    fn lineage_without_tree_fails_cold_replay() {
        let (_directory, mut source) = fixture();
        let project = ProjectId::from_bytes([1; 16]);
        let tree = empty_tree(project, 1);
        let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(source.journal())
            .expect("validator");
        let tree_envelope = hierarchy_reducer_envelope_v1(
            tree_key(project).expect("tree key"),
            1,
            None,
            HierarchyReducerRecordV1::Tree(&tree),
            &validator,
        )
        .expect("tree envelope");
        let link = ClosedTreeLineageRecordV1::new(
            project,
            1,
            None,
            tree_envelope.digest(),
            None,
            tree_commitment_v1(&tree).expect("commitment"),
            Some(packet(project)),
        )
        .expect("lineage");
        let lineage_envelope = hierarchy_reducer_envelope_v1(
            HierarchyProtectedJournalKeyV1::new(
                HierarchyProtectedRecordKindV1::TreeLineage,
                link.identity().to_vec(),
            )
            .expect("lineage key"),
            1,
            None,
            HierarchyReducerRecordV1::TreeLineage(&link),
            &validator,
        )
        .expect("lineage envelope");
        let mut journal =
            claim_hierarchy_protected_journal_v1(source.journal(), validator).expect("claim");
        let plan = journal.plan([8; 16], vec![lineage_envelope]).expect("plan");
        assert!(matches!(
            journal.commit(plan).expect("commit"),
            DomainCommitOutcomeV1::Applied(_)
        ));
        drop(journal);

        assert!(replay_closed_tree_lineage_v1(source.journal()).is_err());
    }

    #[test]
    fn superseded_tree_without_new_link_fails_cold_replay() {
        let (_directory, mut source) = fixture();
        let authority = test_authority();
        let project = ProjectId::from_bytes([1; 16]);
        {
            let mut writer =
                ClosedSourceTreeLineageWriterV1::claim_for_test(&mut source, &authority)
                    .expect("closed writer");
            assert!(matches!(
                writer.append_genesis(packet(project)).expect("genesis"),
                DomainCommitOutcomeV1::Applied(_)
            ));
        }
        let previous = replay_closed_tree_lineage_v1(source.journal())
            .expect("genesis replay")
            .get(&project)
            .expect("project")
            .tree_head;
        commit_tree_only(
            &mut source,
            &empty_tree(project, 2),
            Some(previous),
            [7; 16],
        );

        assert!(replay_closed_tree_lineage_v1(source.journal()).is_err());
    }
}
