//! Canonical reconstructing replay records for durable Git projections.
//!
//! ```text
//! AOSGITH2 | version:1 | kind:1 | reserved:5 | project:16 | repository:16 |
//! lineage:16 | revision:8 | predecessor:32 | atomic-join:16 |
//! join-revision:8 | join-digest:32 | floor:8 | payload-length:4 |
//! canonical-payload | digest:32
//! ```
//!
//! An atomic publication join contains exactly a `Published` receive record,
//! its publication witness, and its repository successor. Other projection
//! transactions contain one complete payload. Replay rejects incomplete,
//! non-contiguous, reused, or digest-divergent joins.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId, Revision};
use sha2::{Digest as _, Sha256};

use super::compaction::{
    decode_retired_pack, encode_retired_pack, encoded_retired_pack_length, preflight_retired_pack,
};
use super::durable_payload::{
    GitDurablePayloadV1, MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES, decode_git_durable_payload_v1,
    encode_git_durable_payload_v1,
};
use super::{
    GitDurableHistoryV1, GitJournalVerifierV1, GitModelError, GitPublicationRecordV1,
    GitReceivePhaseV1, GitRepositoryStateV1, GitRetiredPackSummaryV1, GitTrustedValidatorV1,
};

const MAGIC: &[u8; 8] = b"AOSGITH2";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 172;
const DIGEST_BYTES: usize = 32;
const CHECKPOINT_VERSION: u16 = 2;
const CHECKPOINT_HEADER_BYTES: usize = 92;

/// Maximum Git projection records retained in one replay window.
pub const MAXIMUM_GIT_DURABLE_RECORDS: usize = 262_144;
/// Maximum aggregate canonical bytes retained in one Git replay window.
pub const MAXIMUM_GIT_DURABLE_BYTES: usize = 512 * 1024 * 1024;
/// Maximum members accepted in one atomic Git projection join.
pub const MAXIMUM_GIT_ATOMIC_JOIN_MEMBERS: usize = super::MAXIMUM_GIT_PACK_LEASES + 1;

/// Selects one closed durable Git projection family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GitDurableRecordKindV1 {
    /// Stores a complete repository revision.
    Repository = 1,
    /// Stores receive and quarantine progress.
    Receive = 2,
    /// Stores atomic publication evidence.
    Publication = 3,
    /// Stores an immutable export generation.
    Export = 4,
    /// Stores an immutable pack generation.
    Pack = 5,
    /// Stores pack pin/lease currentness.
    PackLease = 6,
    /// Stores cheap-fork lineage.
    CheapFork = 7,
}

/// Binds one complete canonical Git payload to lineage and atomic identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDurableRecordV1 {
    project: ProjectId,
    repository: ResourceId,
    lineage: ResourceId,
    revision: Revision,
    predecessor: Option<ObjectDigest>,
    payload: GitDurablePayloadV1,
    encoded_payload: Vec<u8>,
    encoded_payload_length: u32,
    atomic_join: ResourceId,
    join_revision: Revision,
    join_digest: ObjectDigest,
    replay_floor: Option<Revision>,
}

impl GitDurableRecordV1 {
    /// Constructs one bounded, reconstructing, non-authorizing Git record.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] for sentinel fields, payload identity mismatch,
    /// broken predecessor shape, invalid replay floor, unrepresentable payload,
    /// or failed bounded allocation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectId,
        repository: ResourceId,
        lineage: ResourceId,
        revision: Revision,
        predecessor: Option<ObjectDigest>,
        payload: GitDurablePayloadV1,
        atomic_join: ResourceId,
        join_revision: Revision,
        join_digest: ObjectDigest,
        replay_floor: Option<Revision>,
    ) -> Result<Self, GitModelError> {
        let (payload_lineage, _) = payload.lineage_revision();
        let scope_matches = match &payload {
            GitDurablePayloadV1::Repository(value) => {
                value.repository().project() == project
                    && value.repository().repository() == repository
            }
            GitDurablePayloadV1::Receive(value) => {
                value.plan().repository().project() == project
                    && value.plan().repository().repository() == repository
            }
            GitDurablePayloadV1::Publication(value) => value.repository() == repository,
            GitDurablePayloadV1::Export(value) => {
                value.export().project() == project && value.export().repository() == repository
            }
            GitDurablePayloadV1::Pack(value) => {
                value.project() == project && value.repository() == repository
            }
            GitDurablePayloadV1::PackLease(value) => {
                value.project() == project && value.repository() == repository
            }
            GitDurablePayloadV1::CheapFork(value) => {
                value.target().repository().project() == project
                    && value.source_repository() == repository
            }
        };
        if project.as_bytes() == &[0; 16]
            || repository.as_bytes() == &[0; 16]
            || lineage.as_bytes() == &[0; 16]
            || lineage != payload_lineage
            || !scope_matches
            || revision.get() == 0
            || revision.get() == u64::MAX
            || (revision.get() == 1) != predecessor.is_none()
            || atomic_join.as_bytes() == &[0; 16]
            || join_revision.get() == 0
            || join_revision.get() == u64::MAX
            || replay_floor.is_some_and(|floor| floor.get() == 0 || floor.get() == u64::MAX)
        {
            return Err(GitModelError::InvalidModel);
        }
        let encoded_payload = encode_git_durable_payload_v1(&payload)?;
        let encoded_payload_length =
            u32::try_from(encoded_payload.len()).map_err(|_| GitModelError::InvalidModel)?;
        Ok(Self {
            project,
            repository,
            lineage,
            revision,
            predecessor,
            payload,
            encoded_payload,
            encoded_payload_length,
            atomic_join,
            join_revision,
            join_digest,
            replay_floor,
        })
    }

    /// Returns the record family.
    #[must_use]
    pub const fn kind(&self) -> GitDurableRecordKindV1 {
        self.payload.kind()
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the repository transaction scope.
    #[must_use]
    pub const fn repository(&self) -> ResourceId {
        self.repository
    }

    /// Returns the family-local lineage.
    #[must_use]
    pub const fn lineage(&self) -> ResourceId {
        self.lineage
    }

    /// Returns the family-local revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the predecessor envelope commitment.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Borrows the complete reconstructing payload.
    #[must_use]
    pub const fn payload(&self) -> &GitDurablePayloadV1 {
        &self.payload
    }

    /// Returns the canonical payload commitment.
    #[must_use]
    pub fn payload_digest(&self) -> ObjectDigest {
        payload_digest(&self.encoded_payload)
    }

    /// Returns the atomic join identity.
    #[must_use]
    pub const fn atomic_join(&self) -> ResourceId {
        self.atomic_join
    }

    /// Returns the joined transaction revision.
    #[must_use]
    pub const fn join_revision(&self) -> Revision {
        self.join_revision
    }

    /// Returns the joined transaction commitment.
    #[must_use]
    pub const fn join_digest(&self) -> ObjectDigest {
        self.join_digest
    }

    /// Returns the replay floor.
    #[must_use]
    pub const fn replay_floor(&self) -> Option<Revision> {
        self.replay_floor
    }

    /// Returns the canonical record commitment.
    #[must_use]
    pub fn complete_digest(&self) -> ObjectDigest {
        durable_record_digest(self)
    }

    fn join_member_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.git.atomic-join-member.v1\0")
                .chain_update(self.project.as_bytes())
                .chain_update(self.repository.as_bytes())
                .chain_update([self.kind() as u8])
                .chain_update(self.lineage.as_bytes())
                .chain_update(self.revision.get().to_be_bytes())
                .chain_update(self.payload_digest().as_bytes())
                .finalize()
                .into(),
        )
    }
}

/// Derives the commitment an atomic record group must carry.
///
/// # Errors
///
/// Returns [`GitModelError::InvalidModel`] for an empty or oversized group or
/// members that do not share one project, repository, join ID, and revision.
pub fn git_atomic_join_digest_v1(
    records: &[GitDurableRecordV1],
) -> Result<ObjectDigest, GitModelError> {
    let first = records.first().ok_or(GitModelError::InvalidModel)?;
    if records.len() > MAXIMUM_GIT_ATOMIC_JOIN_MEMBERS
        || records.iter().any(|record| {
            record.project != first.project
                || record.repository != first.repository
                || record.atomic_join != first.atomic_join
                || record.join_revision != first.join_revision
                || record.replay_floor != first.replay_floor
        })
    {
        return Err(GitModelError::InvalidModel);
    }
    let mut members = Vec::new();
    members
        .try_reserve_exact(records.len())
        .map_err(|_| GitModelError::Allocation)?;
    members.extend(records.iter().map(SelfRecordDigest::new));
    members.sort();
    if members.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(GitModelError::InvalidModel);
    }
    let member_count = u32::try_from(members.len()).map_err(|_| GitModelError::InvalidModel)?;
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.atomic-join.v1\0")
        .chain_update(first.project.as_bytes())
        .chain_update(first.repository.as_bytes())
        .chain_update(first.atomic_join.as_bytes())
        .chain_update(first.join_revision.get().to_be_bytes())
        .chain_update(member_count.to_be_bytes());
    for member in members {
        hasher = hasher.chain_update(member.0.as_bytes());
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

/// Binds a complete proposed group to its derived atomic-join commitment.
///
/// Records may carry a zero join digest only as in-memory proposals. This
/// function commits every member before returning any encodable record.
///
/// # Errors
///
/// Returns [`GitModelError::InvalidModel`] unless the group is uniformly
/// scoped and is one independent record, the exact publication triple, or one
/// pack-lease revision with its complete cheap-fork rebind set.
pub fn bind_git_atomic_join_v1(
    mut records: Vec<GitDurableRecordV1>,
) -> Result<Vec<GitDurableRecordV1>, GitModelError> {
    if !atomic_shape_is_closed(&records) {
        return Err(GitModelError::InvalidModel);
    }
    let digest = git_atomic_join_digest_v1(&records)?;
    for record in &mut records {
        record.join_digest = digest;
    }
    Ok(records)
}

fn atomic_shape_is_closed(records: &[GitDurableRecordV1]) -> bool {
    let publication_shape = records.len() == 3
        && records
            .iter()
            .filter(|record| matches!(record.payload(), GitDurablePayloadV1::Repository(_)))
            .count()
            == 1
        && records
            .iter()
            .filter(|record| matches!(record.payload(), GitDurablePayloadV1::Publication(_)))
            .count()
            == 1
        && records
            .iter()
            .filter(|record| {
                matches!(
                    record.payload(),
                    GitDurablePayloadV1::Receive(value)
                        if value.phase() == GitReceivePhaseV1::Published
                )
            })
            .count()
            == 1;
    let single_shape = records.len() == 1
        && match records[0].payload() {
            GitDurablePayloadV1::Publication(_) => false,
            GitDurablePayloadV1::Receive(value) => value.phase() != GitReceivePhaseV1::Published,
            GitDurablePayloadV1::PackLease(_) => true,
            _ => true,
        };
    let lease_fork_shape = records.len() >= 2
        && records
            .iter()
            .filter(|record| matches!(record.payload(), GitDurablePayloadV1::PackLease(_)))
            .count()
            == 1
        && records.iter().all(|record| {
            matches!(
                record.payload(),
                GitDurablePayloadV1::PackLease(_) | GitDurablePayloadV1::CheapFork(_)
            )
        });
    publication_shape || lease_fork_shape || single_shape
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct SelfRecordDigest(ObjectDigest);

impl SelfRecordDigest {
    fn new(record: &GitDurableRecordV1) -> Self {
        Self(record.join_member_digest())
    }
}

/// Encodes one validated reconstructing Git projection record.
///
/// # Errors
///
/// Returns [`GitModelError`] if the record exceeds its fixed length ceiling or
/// checked allocation fails.
pub fn encode_git_durable_record_v1(record: &GitDurableRecordV1) -> Result<Vec<u8>, GitModelError> {
    if record.join_digest.as_bytes() == &[0; 32] {
        return Err(GitModelError::InvalidModel);
    }
    let body_length = HEADER_BYTES
        .checked_add(record.encoded_payload.len())
        .ok_or(GitModelError::InvalidModel)?;
    let length = body_length
        .checked_add(DIGEST_BYTES)
        .ok_or(GitModelError::InvalidModel)?;
    if length > HEADER_BYTES + MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES + DIGEST_BYTES {
        return Err(GitModelError::InvalidModel);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| GitModelError::Allocation)?;
    append_body(&mut encoded, record);
    if encoded.len() != body_length {
        return Err(GitModelError::InvalidModel);
    }
    let digest = durable_digest(&encoded);
    encoded.extend_from_slice(digest.as_bytes());
    Ok(encoded)
}

/// Decodes one exact bounded reconstructing Git projection record.
///
/// # Errors
///
/// Returns [`GitModelError`] for malformed canonical bytes or validator-bound
/// graph evidence that does not match `trusted_validator`.
pub fn decode_git_durable_record_v1(
    encoded: &[u8],
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitDurableRecordV1, GitModelError> {
    if encoded.len() < HEADER_BYTES + 1 + DIGEST_BYTES
        || encoded.len() > HEADER_BYTES + MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES + DIGEST_BYTES
    {
        return Err(GitModelError::CorruptEncoding);
    }
    let (body, stored) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    if stored != durable_digest(body).as_bytes() {
        return Err(GitModelError::CorruptEncoding);
    }
    let mut bytes = body;
    if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
        return Err(GitModelError::CorruptEncoding);
    }
    let kind = decode_kind(take::<1>(&mut bytes)?[0])?;
    if take::<5>(&mut bytes)? != [0; 5] {
        return Err(GitModelError::CorruptEncoding);
    }
    let project = ProjectId::from_bytes(take(&mut bytes)?);
    let repository = ResourceId::from_bytes(take(&mut bytes)?);
    let lineage = ResourceId::from_bytes(take(&mut bytes)?);
    let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let predecessor = optional_digest(take(&mut bytes)?);
    let atomic_join = ResourceId::from_bytes(take(&mut bytes)?);
    let join_revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let join_digest = ObjectDigest::from_bytes(take(&mut bytes)?);
    if join_digest.as_bytes() == &[0; 32] {
        return Err(GitModelError::CorruptEncoding);
    }
    let floor = u64::from_be_bytes(take(&mut bytes)?);
    let payload_length = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if payload_length == 0 || payload_length > MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES {
        return Err(GitModelError::CorruptEncoding);
    }
    let payload_bytes = take_slice(&mut bytes, payload_length)?;
    if !bytes.is_empty() {
        return Err(GitModelError::CorruptEncoding);
    }
    let payload = decode_git_durable_payload_v1(kind, payload_bytes, trusted_validator)?;
    let record = GitDurableRecordV1::new(
        project,
        repository,
        lineage,
        revision,
        predecessor,
        payload,
        atomic_join,
        join_revision,
        join_digest,
        (floor != 0).then_some(Revision::new(floor)),
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    if record.encoded_payload != payload_bytes {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(record)
}

/// Replays bounded Git projection lineages and exact atomic joins.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GitProjectionHistoryV1 {
    pub(super) latest:
        BTreeMap<(ProjectId, ResourceId, GitDurableRecordKindV1), GitDurableRecordV1>,
    pub(super) records:
        BTreeMap<(ProjectId, ResourceId, GitDurableRecordKindV1, Revision), GitDurableRecordV1>,
    pub(super) joins: BTreeMap<(ProjectId, ResourceId), (ResourceId, Revision, ObjectDigest)>,
    pub(super) join_order: Vec<(ProjectId, ResourceId)>,
    pub(super) domain: GitDurableHistoryV1,
    pub(super) retained_bytes: usize,
    pub(super) summary_bytes: usize,
}

/// Stores a digest-checked reconstructing Git projection replay floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitProjectionCheckpointV1 {
    history: GitProjectionHistoryV1,
    authority: ObjectDigest,
    digest: ObjectDigest,
    accepted_record: Option<ObjectDigest>,
}

impl GitProjectionHistoryV1 {
    /// Replays a bounded canonical stream of contiguous atomic joins.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] for malformed, forked, over-capacity,
    /// incomplete, orphaned, reused, or cross-projection-inconsistent records.
    pub fn replay(
        records: super::GitAcceptedRecordSetV1,
        verifier: &GitJournalVerifierV1,
    ) -> Result<Self, GitModelError> {
        let mut history = Self::default();
        history.replay_suffix(records, verifier)?;
        Ok(history)
    }

    /// Replays a suffix after a digest-checked checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] for a changed checkpoint or invalid suffix.
    pub fn replay_after(
        checkpoint: &GitProjectionCheckpointV1,
        records: super::GitAcceptedRecordSetV1,
        verifier: &GitJournalVerifierV1,
    ) -> Result<Self, GitModelError> {
        if checkpoint.digest != checkpoint.history.complete_digest()
            || checkpoint.authority != verifier.authority()
            || checkpoint
                .accepted_record
                .is_none_or(|digest| !verifier.accepts_checkpoint(digest))
        {
            return Err(GitModelError::InvalidModel);
        }
        let mut history = checkpoint.history.clone();
        history.replay_suffix(records, verifier)?;
        Ok(history)
    }

    fn replay_suffix(
        &mut self,
        records: super::GitAcceptedRecordSetV1,
        verifier: &GitJournalVerifierV1,
    ) -> Result<(), GitModelError> {
        let mut group = Vec::new();
        let mut current_join = None;
        for accepted in records.into_projection(verifier.authority())? {
            let encoded = accepted.payload();
            if encoded.len() > MAXIMUM_GIT_DURABLE_BYTES {
                return Err(GitModelError::InvalidModel);
            }
            let record = decode_git_durable_record_v1(encoded, verifier.validator())?;
            let ownership = accepted.ownership();
            let expected_kind = if record.kind() == GitDurableRecordKindV1::Receive {
                super::GitJournalRecordKindV1::ReceiveEffect
            } else {
                super::GitJournalRecordKindV1::State
            };
            let receive_is_current = match record.payload() {
                GitDurablePayloadV1::Receive(receive) => {
                    matches!(
                        receive.phase(),
                        GitReceivePhaseV1::Published | GitReceivePhaseV1::Rejected
                    ) || ownership.boot_authority() == verifier.current_boottime().boot().digest()
                }
                _ => true,
            };
            if ownership.kind() != expected_kind
                || ownership.project() != record.project
                || ownership.repository() != record.repository
                || ownership.namespace() != record.lineage
                || ownership.revision() != record.revision
                || !receive_is_current
            {
                return Err(GitModelError::InvalidModel);
            }
            let join = (record.project, record.atomic_join);
            if current_join.is_some_and(|current| current != join) {
                self.apply_atomic_inner(&group)?;
                group.clear();
            }
            if group.len() >= MAXIMUM_GIT_ATOMIC_JOIN_MEMBERS {
                return Err(GitModelError::InvalidModel);
            }
            group
                .try_reserve(1)
                .map_err(|_| GitModelError::Allocation)?;
            current_join = Some(join);
            group.push(record);
        }
        if !group.is_empty() {
            self.apply_atomic_inner(&group)?;
        }
        self.domain.validate_current_leases(verifier)?;
        Ok(())
    }

    /// Applies one complete atomic projection group.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a fork, orphan member,
    /// incomplete publication triple, reused join, or changed join digest.
    pub fn apply_atomic_at(
        &mut self,
        records: super::GitAcceptedRecordSetV1,
        verifier: &GitJournalVerifierV1,
    ) -> Result<(), GitModelError> {
        let mut next = self.clone();
        let expected_joins = self
            .joins
            .len()
            .checked_add(1)
            .ok_or(GitModelError::InvalidModel)?;
        next.replay_suffix(records, verifier)?;
        if next.joins.len() != expected_joins {
            return Err(GitModelError::InvalidModel);
        }
        *self = next;
        Ok(())
    }

    fn apply_atomic_inner(&mut self, records: &[GitDurableRecordV1]) -> Result<(), GitModelError> {
        let first = records.first().ok_or(GitModelError::InvalidModel)?;
        let expected_join_digest = git_atomic_join_digest_v1(records)?;
        if records
            .iter()
            .any(|record| record.join_digest != expected_join_digest)
            || self.joins.contains_key(&(first.project, first.atomic_join))
        {
            return Err(GitModelError::InvalidModel);
        }

        let mut next = self.clone();
        next.synchronize_floor(first.replay_floor)?;
        for record in records {
            let record_length = encode_git_durable_record_v1(record)?
                .len()
                .checked_add(4)
                .ok_or(GitModelError::InvalidModel)?;
            next.retained_bytes = next
                .retained_bytes
                .checked_add(record_length)
                .filter(|value| {
                    value
                        .checked_add(next.summary_bytes)
                        .and_then(|total| total.checked_add(CHECKPOINT_HEADER_BYTES + DIGEST_BYTES))
                        .is_some_and(|total| total <= MAXIMUM_GIT_DURABLE_BYTES)
                })
                .ok_or(GitModelError::InvalidModel)?;
        }
        next.validate_lineages(records)?;
        next.apply_domain_join(records)?;
        for record in records {
            let key = (record.project, record.lineage, record.kind());
            next.latest.insert(key, record.clone());
            next.records.insert(
                (
                    record.project,
                    record.lineage,
                    record.kind(),
                    record.revision,
                ),
                record.clone(),
            );
        }
        next.joins.insert(
            (first.project, first.atomic_join),
            (first.repository, first.join_revision, first.join_digest),
        );
        next.join_order.push((first.project, first.atomic_join));
        *self = next;
        Ok(())
    }

    fn synchronize_floor(&mut self, floor: Option<Revision>) -> Result<(), GitModelError> {
        if floor == self.domain.replay_floor() {
            return Ok(());
        }
        let floor = floor.ok_or(GitModelError::InvalidModel)?;
        self.domain.advance_replay_floor(floor)?;
        Ok(())
    }

    /// Compacts protected domain indexes at the exact synchronized floor.
    ///
    /// Projection records remain as the reconstructing predecessor closure;
    /// only derived domain indexes discard superseded phase snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless both histories name the
    /// same already-advanced floor or a closed replacement would exceed its
    /// count or byte ceilings. Returns [`GitModelError::Allocation`] if a
    /// bounded reservation fails.
    pub fn compact_protected_floor(&mut self, floor: Revision) -> Result<(), GitModelError> {
        let mut next = self.clone();
        next.compact_protected_floor_inner(floor)?;
        *self = next;
        Ok(())
    }

    fn compact_protected_floor_inner(&mut self, floor: Revision) -> Result<(), GitModelError> {
        if self.domain.replay_floor() != Some(floor) {
            return Err(GitModelError::InvalidModel);
        }
        let (retired_packs, discarded_joins) = self.plan_pack_retirements(floor)?;
        self.domain
            .install_retired_pack_summaries(&retired_packs, floor)?;
        self.records
            .retain(|_, record| !discarded_joins.contains(&(record.project, record.atomic_join)));
        let retained_summarized_lineage =
            self.records.values().any(|record| match record.payload() {
                GitDurablePayloadV1::Pack(value) => self
                    .domain
                    .retired_packs
                    .contains_key(&(value.pack_generation(), value.generation())),
                GitDurablePayloadV1::PackLease(value) => self
                    .domain
                    .terminal_lease_tombstones
                    .contains_key(&value.lease()),
                GitDurablePayloadV1::CheapFork(value) => self
                    .domain
                    .terminal_fork_tombstones
                    .contains_key(&value.target().repository().repository()),
                _ => false,
            });
        if retained_summarized_lineage {
            return Err(GitModelError::InvalidModel);
        }
        self.latest.clear();
        for record in self.records.values() {
            let key = (record.project, record.lineage, record.kind());
            if self
                .latest
                .get(&key)
                .is_none_or(|current| current.revision < record.revision)
            {
                self.latest.insert(key, record.clone());
            }
        }
        self.domain.compact_at_floor(floor)?;
        let mut retained_joins = Vec::new();
        retained_joins
            .try_reserve_exact(
                self.records
                    .len()
                    .checked_add(self.latest.len())
                    .ok_or(GitModelError::InvalidModel)?,
            )
            .map_err(|_| GitModelError::Allocation)?;
        retained_joins.extend(
            self.records
                .values()
                .filter(|record| self.domain.contains_checkpoint_payload(record.payload()))
                .map(|record| (record.project, record.atomic_join)),
        );
        retained_joins.extend(
            self.latest
                .values()
                .map(|record| (record.project, record.atomic_join)),
        );
        retained_joins.sort_unstable();
        retained_joins.dedup();
        self.records.retain(|_, record| {
            retained_joins
                .binary_search(&(record.project, record.atomic_join))
                .is_ok()
        });
        self.joins
            .retain(|join, _| retained_joins.binary_search(join).is_ok());
        self.join_order
            .retain(|join| retained_joins.binary_search(join).is_ok());
        self.retained_bytes = 0;
        for record in self.records.values() {
            let record_length = encode_git_durable_record_v1(record)?
                .len()
                .checked_add(4)
                .ok_or(GitModelError::InvalidModel)?;
            self.retained_bytes = self
                .retained_bytes
                .checked_add(record_length)
                .filter(|value| *value <= MAXIMUM_GIT_DURABLE_BYTES)
                .ok_or(GitModelError::InvalidModel)?;
        }
        self.summary_bytes = self
            .domain
            .retired_packs
            .values()
            .try_fold(0_usize, |total, summary| {
                total
                    .checked_add(4)?
                    .checked_add(encoded_retired_pack_length(summary).ok()?)
            })
            .ok_or(GitModelError::InvalidModel)?;
        if self
            .retained_bytes
            .checked_add(self.summary_bytes)
            .and_then(|total| total.checked_add(CHECKPOINT_HEADER_BYTES + DIGEST_BYTES))
            .is_none_or(|total| total > MAXIMUM_GIT_DURABLE_BYTES)
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(())
    }

    fn from_checkpoint_records(
        records: Vec<GitDurableRecordV1>,
        retired_packs: Vec<GitRetiredPackSummaryV1>,
        expected_floor: Revision,
        verifier: &GitJournalVerifierV1,
    ) -> Result<Self, GitModelError> {
        let mut history = Self::default();
        let mut offset = 0_usize;
        let mut floor = None;
        while offset < records.len() {
            let first = &records[offset];
            let join = (first.project, first.atomic_join);
            let end = records[offset..]
                .iter()
                .position(|record| (record.project, record.atomic_join) != join)
                .map_or(records.len(), |relative| offset + relative);
            let members = &records[offset..end];
            let digest = git_atomic_join_digest_v1(members)?;
            if !atomic_shape_is_closed(members)
                || history.joins.contains_key(&join)
                || members.iter().any(|record| {
                    record.join_digest != digest
                        || record.repository != first.repository
                        || record.join_revision != first.join_revision
                        || record.replay_floor != first.replay_floor
                })
            {
                return Err(GitModelError::InvalidModel);
            }
            history.joins.insert(
                join,
                (first.repository, first.join_revision, first.join_digest),
            );
            history.join_order.push(join);
            if let Some(next_floor) = first.replay_floor {
                if floor.is_some_and(|current| next_floor < current) {
                    return Err(GitModelError::InvalidModel);
                }
                floor = Some(next_floor);
            }
            offset = end;
        }
        let floor = floor.unwrap_or(expected_floor);
        if floor != expected_floor {
            return Err(GitModelError::InvalidModel);
        }
        for record in records {
            let record_length = encode_git_durable_record_v1(&record)?
                .len()
                .checked_add(4)
                .ok_or(GitModelError::InvalidModel)?;
            history.retained_bytes = history
                .retained_bytes
                .checked_add(record_length)
                .filter(|value| *value <= MAXIMUM_GIT_DURABLE_BYTES)
                .ok_or(GitModelError::InvalidModel)?;
            let record_key = (
                record.project,
                record.lineage,
                record.kind(),
                record.revision,
            );
            if history.records.insert(record_key, record.clone()).is_some() {
                return Err(GitModelError::InvalidModel);
            }
            let lineage_key = (record.project, record.lineage, record.kind());
            if history
                .latest
                .get(&lineage_key)
                .is_none_or(|current| current.revision < record.revision)
            {
                history.latest.insert(lineage_key, record);
            }
        }
        history.domain = GitDurableHistoryV1::from_compacted_payloads(
            history.records.values().map(GitDurableRecordV1::payload),
            retired_packs,
            floor,
            verifier,
        )?;
        history.summary_bytes = history
            .domain
            .retired_packs
            .values()
            .try_fold(0_usize, |total, summary| {
                total
                    .checked_add(4)?
                    .checked_add(encoded_retired_pack_length(summary).ok()?)
            })
            .ok_or(GitModelError::InvalidModel)?;
        if history
            .retained_bytes
            .checked_add(history.summary_bytes)
            .and_then(|total| total.checked_add(CHECKPOINT_HEADER_BYTES + DIGEST_BYTES))
            .is_none_or(|total| total > MAXIMUM_GIT_DURABLE_BYTES)
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(history)
    }

    fn validate_lineages(&self, records: &[GitDurableRecordV1]) -> Result<(), GitModelError> {
        if self
            .records
            .len()
            .checked_add(records.len())
            .is_none_or(|count| count > MAXIMUM_GIT_DURABLE_RECORDS)
        {
            return Err(GitModelError::InvalidModel);
        }
        let mut keys = BTreeSet::new();
        for record in records {
            let key = (record.project, record.lineage, record.kind());
            if !keys.insert(key) {
                return Err(GitModelError::InvalidModel);
            }
            if let Some(previous) = self.latest.get(&key) {
                if previous.repository != record.repository
                    || !previous
                        .revision
                        .checked_next()
                        .is_ok_and(|next| next == record.revision)
                    || record.predecessor != Some(previous.complete_digest())
                    || previous
                        .replay_floor
                        .is_some_and(|floor| record.replay_floor.is_none_or(|next| next < floor))
                {
                    return Err(GitModelError::InvalidModel);
                }
            } else if let Some(previous) =
                self.domain
                    .retired_lineage_head(record.project, record.lineage, record.kind())
            {
                if !previous
                    .0
                    .checked_next()
                    .is_ok_and(|revision| revision == record.revision)
                    || record.predecessor != Some(previous.1)
                {
                    return Err(GitModelError::InvalidModel);
                }
            } else if record.revision.get() != 1 || record.predecessor.is_some() {
                return Err(GitModelError::InvalidModel);
            }
        }
        Ok(())
    }

    fn apply_domain_join(&mut self, records: &[GitDurableRecordV1]) -> Result<(), GitModelError> {
        if records.len() == 1 {
            return match records[0].payload() {
                GitDurablePayloadV1::Repository(value) => {
                    self.domain.apply_repository(value.clone())
                }
                GitDurablePayloadV1::Receive(value)
                    if value.phase() != GitReceivePhaseV1::Published =>
                {
                    self.domain.apply_receive(value.clone())
                }
                GitDurablePayloadV1::Export(value) => self.domain.apply_export(value.clone()),
                GitDurablePayloadV1::Pack(value) => self.domain.apply_pack(value.clone()),
                GitDurablePayloadV1::PackLease(value) => match value.consumer() {
                    super::GitPackConsumerV1::Repository(_) => {
                        self.domain.apply_pack_lease_with_forks(*value, &[])
                    }
                    super::GitPackConsumerV1::Export(_) => {
                        self.domain.apply_replayed_pack_lease(*value)
                    }
                },
                GitDurablePayloadV1::CheapFork(value) => {
                    self.domain.apply_replayed_cheap_fork(value.clone())
                }
                GitDurablePayloadV1::Receive(_) | GitDurablePayloadV1::Publication(_) => {
                    Err(GitModelError::InvalidModel)
                }
            };
        }
        if records
            .iter()
            .any(|record| matches!(record.payload(), GitDurablePayloadV1::PackLease(_)))
        {
            let lease = records.iter().find_map(|record| match record.payload() {
                GitDurablePayloadV1::PackLease(value) => Some(*value),
                _ => None,
            });
            let fork_count = records
                .len()
                .checked_sub(1)
                .ok_or(GitModelError::InvalidModel)?;
            let mut forks = Vec::new();
            forks
                .try_reserve_exact(fork_count)
                .map_err(|_| GitModelError::Allocation)?;
            forks.extend(records.iter().filter_map(|record| match record.payload() {
                GitDurablePayloadV1::CheapFork(value) => Some(value.clone()),
                _ => None,
            }));
            return self
                .domain
                .apply_pack_lease_with_forks(lease.ok_or(GitModelError::InvalidModel)?, &forks);
        }
        if records.len() != 3 {
            return Err(GitModelError::InvalidModel);
        }
        let receive = records.iter().find_map(|record| match record.payload() {
            GitDurablePayloadV1::Receive(value)
                if value.phase() == GitReceivePhaseV1::Published =>
            {
                Some(value)
            }
            _ => None,
        });
        let publication = records.iter().find_map(|record| match record.payload() {
            GitDurablePayloadV1::Publication(value) => Some(*value),
            _ => None,
        });
        let repository = records.iter().find_map(|record| match record.payload() {
            GitDurablePayloadV1::Repository(value) => Some(value),
            _ => None,
        });
        let (Some(receive), Some(publication), Some(repository)) =
            (receive, publication, repository)
        else {
            return Err(GitModelError::InvalidModel);
        };
        let expected_publication =
            GitPublicationRecordV1::from_receive(receive.plan(), publication.published_at())?;
        let current = self
            .domain
            .repository(receive.plan().repository().repository())
            .ok_or(GitModelError::InvalidModel)?;
        let expected_repository =
            GitRepositoryStateV1::from_receive(receive.plan(), current.complete_digest())?;
        if publication != expected_publication || repository != &expected_repository {
            return Err(GitModelError::InvalidModel);
        }
        self.domain
            .apply_published_receive(receive.clone(), publication.published_at())
    }

    /// Captures the current bounded materialization.
    #[must_use]
    pub fn checkpoint(&self, verifier: &GitJournalVerifierV1) -> GitProjectionCheckpointV1 {
        GitProjectionCheckpointV1 {
            history: self.clone(),
            authority: verifier.authority(),
            digest: self.complete_digest(),
            accepted_record: None,
        }
    }

    /// Borrows the fully reconstructed domain history.
    #[must_use]
    pub const fn domain_history(&self) -> &GitDurableHistoryV1 {
        &self.domain
    }

    fn complete_digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.git.projection-checkpoint.v2\0")
            .chain_update((self.retained_bytes as u64).to_be_bytes())
            .chain_update((self.summary_bytes as u64).to_be_bytes())
            .chain_update(
                self.domain
                    .replay_floor()
                    .map_or(0, Revision::get)
                    .to_be_bytes(),
            );
        for (key, record) in &self.latest {
            hasher = hasher
                .chain_update(key.0.as_bytes())
                .chain_update(key.1.as_bytes())
                .chain_update([key.2 as u8])
                .chain_update(record.complete_digest().as_bytes());
        }
        for (key, record) in &self.records {
            hasher = hasher
                .chain_update(key.0.as_bytes())
                .chain_update(key.1.as_bytes())
                .chain_update([key.2 as u8])
                .chain_update(key.3.get().to_be_bytes())
                .chain_update(record.complete_digest().as_bytes());
        }
        for ((project, id), (repository, revision, digest)) in &self.joins {
            hasher = hasher
                .chain_update(project.as_bytes())
                .chain_update(id.as_bytes())
                .chain_update(repository.as_bytes())
                .chain_update(revision.get().to_be_bytes())
                .chain_update(digest.as_bytes());
        }
        for ((identity, generation), summary) in &self.domain.retired_packs {
            hasher = hasher
                .chain_update([0x50])
                .chain_update(identity.as_bytes())
                .chain_update(generation.get().to_be_bytes())
                .chain_update(summary.project.as_bytes())
                .chain_update(summary.repository.as_bytes())
                .chain_update(summary.generation_digest.digest().as_bytes())
                .chain_update(summary.pack_payload_digest.as_bytes())
                .chain_update(summary.pack_record_head.as_bytes())
                .chain_update(summary.retired_at_floor.get().to_be_bytes());
            for lease in &summary.leases {
                hasher = hasher
                    .chain_update([0x4c])
                    .chain_update(lease.lease.as_bytes())
                    .chain_update(lease.revision.get().to_be_bytes())
                    .chain_update([lease.outcome as u8])
                    .chain_update(lease.payload_digest.as_bytes())
                    .chain_update(lease.record_head.as_bytes());
            }
            for fork in &summary.forks {
                hasher = hasher
                    .chain_update([0x46])
                    .chain_update(fork.target.as_bytes())
                    .chain_update(fork.revision.get().to_be_bytes())
                    .chain_update([fork.outcome as u8])
                    .chain_update(fork.payload_digest.as_bytes())
                    .chain_update(fork.record_head.as_bytes());
            }
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

impl GitProjectionCheckpointV1 {
    /// Returns the complete checkpoint commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Encodes a complete reconstructing Git checkpoint in canonical join order.
///
/// # Errors
///
/// Returns [`GitModelError`] if aggregate size/count ceilings are exceeded or
/// a retained record cannot be encoded.
pub fn encode_git_projection_checkpoint_v1(
    checkpoint: &GitProjectionCheckpointV1,
) -> Result<Vec<u8>, GitModelError> {
    if checkpoint.digest != checkpoint.history.complete_digest()
        || checkpoint.history.records.len() > MAXIMUM_GIT_DURABLE_RECORDS
    {
        return Err(GitModelError::InvalidModel);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(checkpoint.history.records.len())
        .map_err(|_| GitModelError::Allocation)?;
    for join in &checkpoint.history.join_order {
        for record in checkpoint
            .history
            .records
            .values()
            .filter(|record| (record.project, record.atomic_join) == *join)
        {
            records.push(encode_git_durable_record_v1(record)?);
        }
    }
    let mut summaries = Vec::new();
    summaries
        .try_reserve_exact(checkpoint.history.domain.retired_packs.len())
        .map_err(|_| GitModelError::Allocation)?;
    for summary in checkpoint.history.domain.retired_packs.values() {
        let length = encoded_retired_pack_length(summary)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(length)
            .map_err(|_| GitModelError::Allocation)?;
        encode_retired_pack(&mut encoded, summary)?;
        if encoded.len() != length {
            return Err(GitModelError::InvalidModel);
        }
        summaries.push(encoded);
    }
    let body_bytes = records
        .iter()
        .try_fold(CHECKPOINT_HEADER_BYTES, |total, record| {
            total.checked_add(4)?.checked_add(record.len())
        })
        .ok_or(GitModelError::InvalidModel)?;
    let body_bytes = summaries
        .iter()
        .try_fold(body_bytes, |total, summary| {
            total.checked_add(4)?.checked_add(summary.len())
        })
        .ok_or(GitModelError::InvalidModel)?;
    let length = body_bytes
        .checked_add(DIGEST_BYTES)
        .filter(|value| *value <= MAXIMUM_GIT_DURABLE_BYTES)
        .ok_or(GitModelError::InvalidModel)?;
    let record_count = u32::try_from(records.len()).map_err(|_| GitModelError::InvalidModel)?;
    let summary_count = u32::try_from(summaries.len()).map_err(|_| GitModelError::InvalidModel)?;
    let floor = checkpoint
        .history
        .domain
        .replay_floor()
        .ok_or(GitModelError::InvalidModel)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| GitModelError::Allocation)?;
    encoded.extend_from_slice(b"AOSGITCP");
    encoded.extend_from_slice(&CHECKPOINT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&[0; 2]);
    encoded.extend_from_slice(&record_count.to_be_bytes());
    encoded.extend_from_slice(&summary_count.to_be_bytes());
    encoded.extend_from_slice(&floor.get().to_be_bytes());
    encoded.extend_from_slice(checkpoint.authority.as_bytes());
    encoded.extend_from_slice(checkpoint.digest.as_bytes());
    for record in records {
        let record_length = u32::try_from(record.len()).map_err(|_| GitModelError::InvalidModel)?;
        encoded.extend_from_slice(&record_length.to_be_bytes());
        encoded.extend_from_slice(&record);
    }
    for summary in summaries {
        let summary_length =
            u32::try_from(summary.len()).map_err(|_| GitModelError::InvalidModel)?;
        encoded.extend_from_slice(&summary_length.to_be_bytes());
        encoded.extend_from_slice(&summary);
    }
    let digest = durable_digest(&encoded);
    encoded.extend_from_slice(digest.as_bytes());
    Ok(encoded)
}

/// Decodes and fully replays a canonical Git projection checkpoint.
///
/// # Errors
///
/// Returns [`GitModelError`] for malformed bounds, changed digest, invalid
/// records, orphan joins, or mismatched trusted validator evidence.
pub fn decode_git_projection_checkpoint_v1(
    encoded: &[u8],
    verifier: &GitJournalVerifierV1,
) -> Result<GitProjectionCheckpointV1, GitModelError> {
    if encoded.len() < CHECKPOINT_HEADER_BYTES + DIGEST_BYTES
        || encoded.len() > MAXIMUM_GIT_DURABLE_BYTES
    {
        return Err(GitModelError::CorruptEncoding);
    }
    let (body, stored_digest) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    let checkpoint_record = ObjectDigest::from_bytes(
        stored_digest
            .try_into()
            .map_err(|_| GitModelError::CorruptEncoding)?,
    );
    if durable_digest(body) != checkpoint_record || !verifier.accepts_checkpoint(checkpoint_record)
    {
        return Err(GitModelError::CorruptEncoding);
    }
    let mut preflight = body;
    if take::<8>(&mut preflight)? != *b"AOSGITCP"
        || u16::from_be_bytes(take(&mut preflight)?) != CHECKPOINT_VERSION
        || take::<2>(&mut preflight)? != [0; 2]
    {
        return Err(GitModelError::CorruptEncoding);
    }
    let count = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if count > MAXIMUM_GIT_DURABLE_RECORDS {
        return Err(GitModelError::CorruptEncoding);
    }
    let summary_count = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    let floor = Revision::new(u64::from_be_bytes(take(&mut preflight)?));
    if summary_count > super::MAXIMUM_GIT_RETIRED_PACKS
        || floor.get() == 0
        || floor.get() == u64::MAX
    {
        return Err(GitModelError::CorruptEncoding);
    }
    let authority = ObjectDigest::from_bytes(take(&mut preflight)?);
    if authority != verifier.authority() {
        return Err(GitModelError::CorruptEncoding);
    }
    let expected = ObjectDigest::from_bytes(take(&mut preflight)?);
    for _ in 0..count {
        let length = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
            .map_err(|_| GitModelError::CorruptEncoding)?;
        if length < HEADER_BYTES + 1 + DIGEST_BYTES
            || length > HEADER_BYTES + MAXIMUM_GIT_DURABLE_PAYLOAD_BYTES + DIGEST_BYTES
        {
            return Err(GitModelError::CorruptEncoding);
        }
        take_slice(&mut preflight, length)?;
    }
    let mut terminal_lease_count = 0_usize;
    let mut terminal_fork_count = 0_usize;
    for _ in 0..summary_count {
        let length = usize::try_from(u32::from_be_bytes(take(&mut preflight)?))
            .map_err(|_| GitModelError::CorruptEncoding)?;
        if length < super::compaction::encoded_retired_pack_length_minimum()
            || length > MAXIMUM_GIT_DURABLE_BYTES
        {
            return Err(GitModelError::CorruptEncoding);
        }
        let summary = take_slice(&mut preflight, length)?;
        let (lease_count, fork_count) = preflight_retired_pack(summary)?;
        terminal_lease_count = terminal_lease_count
            .checked_add(lease_count)
            .filter(|count| *count <= super::MAXIMUM_GIT_TERMINAL_LEASE_TOMBSTONES)
            .ok_or(GitModelError::CorruptEncoding)?;
        terminal_fork_count = terminal_fork_count
            .checked_add(fork_count)
            .filter(|count| *count <= super::MAXIMUM_GIT_HISTORY_RECORDS)
            .ok_or(GitModelError::CorruptEncoding)?;
    }
    if !preflight.is_empty() {
        return Err(GitModelError::CorruptEncoding);
    }
    let mut bytes = &body[CHECKPOINT_HEADER_BYTES..];
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| GitModelError::Allocation)?;
    for _ in 0..count {
        let length = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
            .map_err(|_| GitModelError::CorruptEncoding)?;
        records.push(decode_git_durable_record_v1(
            take_slice(&mut bytes, length)?,
            verifier.validator(),
        )?);
    }
    let mut summaries = Vec::new();
    summaries
        .try_reserve_exact(summary_count)
        .map_err(|_| GitModelError::Allocation)?;
    for _ in 0..summary_count {
        let length = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
            .map_err(|_| GitModelError::CorruptEncoding)?;
        summaries.push(decode_retired_pack(take_slice(&mut bytes, length)?, floor)?);
    }
    let history =
        GitProjectionHistoryV1::from_checkpoint_records(records, summaries, floor, verifier)?;
    if history.complete_digest() != expected {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(GitProjectionCheckpointV1 {
        history,
        authority,
        digest: expected,
        accepted_record: Some(checkpoint_record),
    })
}

fn append_body(bytes: &mut Vec<u8>, record: &GitDurableRecordV1) {
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(record.kind() as u8);
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(record.project.as_bytes());
    bytes.extend_from_slice(record.repository.as_bytes());
    bytes.extend_from_slice(record.lineage.as_bytes());
    bytes.extend_from_slice(&record.revision.get().to_be_bytes());
    bytes.extend_from_slice(
        record
            .predecessor
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    bytes.extend_from_slice(record.atomic_join.as_bytes());
    bytes.extend_from_slice(&record.join_revision.get().to_be_bytes());
    bytes.extend_from_slice(record.join_digest.as_bytes());
    bytes.extend_from_slice(&record.replay_floor.map_or(0, Revision::get).to_be_bytes());
    bytes.extend_from_slice(&record.encoded_payload_length.to_be_bytes());
    bytes.extend_from_slice(&record.encoded_payload);
}

fn durable_record_digest(record: &GitDurableRecordV1) -> ObjectDigest {
    let predecessor = record
        .predecessor
        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]));
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.durable-record.v2\0")
        .chain_update(MAGIC)
        .chain_update(VERSION.to_be_bytes())
        .chain_update([record.kind() as u8])
        .chain_update([0; 5])
        .chain_update(record.project.as_bytes())
        .chain_update(record.repository.as_bytes())
        .chain_update(record.lineage.as_bytes())
        .chain_update(record.revision.get().to_be_bytes())
        .chain_update(predecessor.as_bytes())
        .chain_update(record.atomic_join.as_bytes())
        .chain_update(record.join_revision.get().to_be_bytes())
        .chain_update(record.join_digest.as_bytes())
        .chain_update(record.replay_floor.map_or(0, Revision::get).to_be_bytes())
        .chain_update(record.encoded_payload_length.to_be_bytes());
    hasher.update(&record.encoded_payload);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn durable_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.durable-record.v2\0")
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn payload_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.durable-payload.v1\0")
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn optional_digest(bytes: [u8; 32]) -> Option<ObjectDigest> {
    (bytes != [0; 32]).then_some(ObjectDigest::from_bytes(bytes))
}

fn decode_kind(value: u8) -> Result<GitDurableRecordKindV1, GitModelError> {
    match value {
        1 => Ok(GitDurableRecordKindV1::Repository),
        2 => Ok(GitDurableRecordKindV1::Receive),
        3 => Ok(GitDurableRecordKindV1::Publication),
        4 => Ok(GitDurableRecordKindV1::Export),
        5 => Ok(GitDurableRecordKindV1::Pack),
        6 => Ok(GitDurableRecordKindV1::PackLease),
        7 => Ok(GitDurableRecordKindV1::CheapFork),
        _ => Err(GitModelError::CorruptEncoding),
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], GitModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| GitModelError::CorruptEncoding)
}

fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], GitModelError> {
    let (head, tail) = bytes
        .split_at_checked(length)
        .ok_or(GitModelError::CorruptEncoding)?;
    *bytes = tail;
    Ok(head)
}
