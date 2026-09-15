//! Inert Git journal namespace ownership model.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId, Revision};
use sha2::{Digest as _, Sha256};

use super::{GitBoottimeV1, GitModelError, GitTrustedBoottimeV1, GitTrustedValidatorV1};

const MAGIC: &[u8; 8] = b"AOSGITJ1";
const VERSION: u16 = 1;
const BODY_BYTES: usize = 240;
const RECORD_BYTES: usize = BODY_BYTES + 32;
const MAXIMUM_GIT_JOURNAL_RECORDS: usize = 262_144;
const MAXIMUM_GIT_CUSTODIED_PAYLOAD_BYTES: usize = 160 * 1024 * 1024;

/// Identifies the dormant Git journal namespace format.
pub const GIT_JOURNAL_NAMESPACE_V1: &str = "aos.sandbox.git.v1";

/// Names the existing shared-journal keyspace used by one Git record family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GitJournalRecordKindV1 {
    /// Stores repository, export, pack, lease, and fork durable state.
    State = 1,
    /// Stores receive/quarantine effect progress.
    ReceiveEffect = 2,
    /// Stores a validator-bound projection checkpoint and protected floor.
    Checkpoint = 3,
}

impl GitJournalRecordKindV1 {
    /// Maps this dormant record kind to the existing shared journal namespace.
    #[must_use]
    pub const fn record_namespace(self) -> crate::journal::RecordNamespace {
        match self {
            Self::State => crate::journal::RecordNamespace::DesiredState,
            Self::ReceiveEffect => crate::journal::RecordNamespace::Effect,
            Self::Checkpoint => crate::journal::RecordNamespace::RuntimeGeneration,
        }
    }
}

/// Binds a Git record to one project and repository namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitJournalOwnershipRecordV1 {
    kind: GitJournalRecordKindV1,
    project: ProjectId,
    repository: ResourceId,
    namespace: ResourceId,
    revision: Revision,
    predecessor: Option<ObjectDigest>,
    record: ObjectDigest,
    journal_authority: ObjectDigest,
    validator_authority: ObjectDigest,
    boot_authority: ObjectDigest,
    replay_floor: Option<Revision>,
}

impl GitJournalOwnershipRecordV1 {
    /// Constructs one non-authorizing namespace record.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for sentinel fields, a broken
    /// first-record shape, or replay floor above the current revision.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: GitJournalRecordKindV1,
        project: ProjectId,
        repository: ResourceId,
        namespace: ResourceId,
        revision: Revision,
        predecessor: Option<ObjectDigest>,
        record: ObjectDigest,
        journal_authority: ObjectDigest,
        validator_authority: ObjectDigest,
        boot_authority: ObjectDigest,
        replay_floor: Option<Revision>,
    ) -> Result<Self, GitModelError> {
        if project.as_bytes() == &[0; 16]
            || repository.as_bytes() == &[0; 16]
            || namespace.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
            || record.as_bytes() == &[0; 32]
            || journal_authority.as_bytes() == &[0; 32]
            || validator_authority.as_bytes() == &[0; 32]
            || boot_authority.as_bytes() == &[0; 32]
            || (revision.get() == 1) != predecessor.is_none()
            || replay_floor.is_some_and(|floor| {
                floor.get() == 0 || floor.get() == u64::MAX || floor.get() > revision.get()
            })
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            kind,
            project,
            repository,
            namespace,
            revision,
            predecessor,
            record,
            journal_authority,
            validator_authority,
            boot_authority,
            replay_floor,
        })
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }
    /// Returns the repository lineage identity.
    #[must_use]
    pub const fn repository(self) -> ResourceId {
        self.repository
    }
    /// Returns the isolated journal namespace identity.
    #[must_use]
    pub const fn namespace(self) -> ResourceId {
        self.namespace
    }
    /// Returns the exact Git record family.
    #[must_use]
    pub const fn kind(self) -> GitJournalRecordKindV1 {
        self.kind
    }
    /// Returns the namespace-local revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }
    /// Returns the exact predecessor commitment.
    #[must_use]
    pub const fn predecessor(self) -> Option<ObjectDigest> {
        self.predecessor
    }
    /// Returns the complete owned record commitment.
    #[must_use]
    pub const fn record(self) -> ObjectDigest {
        self.record
    }
    /// Returns the journal-custody authority commitment.
    #[must_use]
    pub const fn journal_authority(self) -> ObjectDigest {
        self.journal_authority
    }
    /// Returns the opaque validator/checkpoint authority commitment.
    #[must_use]
    pub const fn validator_authority(self) -> ObjectDigest {
        self.validator_authority
    }
    /// Returns the exact kernel-boot clock authority commitment.
    #[must_use]
    pub const fn boot_authority(self) -> ObjectDigest {
        self.boot_authority
    }
    /// Returns the trusted replay floor.
    #[must_use]
    pub const fn replay_floor(self) -> Option<Revision> {
        self.replay_floor
    }

    /// Returns the complete canonical journal-custody commitment.
    #[must_use]
    pub fn complete_digest(self) -> ObjectDigest {
        journal_digest(&encode_body(self))
    }
}

/// Carries trusted dormant Git journal, validator, and boot-clock state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitJournalVerifierV1 {
    authority: ObjectDigest,
    validator: GitTrustedValidatorV1,
    current_boottime: GitTrustedBoottimeV1,
    boot_rollover: GitBootRolloverAuthorityV1,
    accepted_records: Vec<ObjectDigest>,
    accepted_checkpoints: Vec<ObjectDigest>,
}

/// Proves the authenticated predecessor boots eligible for current-boot Git
/// lease and cheap-fork reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitBootRolloverAuthorityV1 {
    attestation: ObjectDigest,
    current: super::GitBootIdV1,
    predecessors: Vec<ObjectDigest>,
}

/// Carries one verifier-accepted Git custody record and its exact payload.
#[derive(Debug, Eq, PartialEq)]
pub struct GitAcceptedRecordV1 {
    ownership: GitJournalOwnershipRecordV1,
    custody_digest: ObjectDigest,
    payload: Vec<u8>,
}

/// Carries every and only verifier-accepted record in one projection suffix.
#[derive(Debug, Eq, PartialEq)]
pub struct GitAcceptedRecordSetV1 {
    authority: ObjectDigest,
    root: ObjectDigest,
    records: Vec<GitAcceptedRecordV1>,
}

impl GitJournalVerifierV1 {
    pub(crate) fn from_verified_state(
        authority: ObjectDigest,
        validator_attestation: ObjectDigest,
        boot: ObjectDigest,
        current_boottime: GitBoottimeV1,
        boot_rollover_attestation: ObjectDigest,
        authenticated_predecessor_boots: Vec<ObjectDigest>,
        accepted_graphs: Vec<ObjectDigest>,
        accepted_ancestry: Vec<ObjectDigest>,
        accepted_validation_reports: Vec<ObjectDigest>,
        accepted_records: Vec<ObjectDigest>,
        accepted_checkpoints: Vec<ObjectDigest>,
    ) -> Result<Self, GitModelError> {
        if authority.as_bytes() == &[0; 32]
            || boot_rollover_attestation.as_bytes() == &[0; 32]
            || authenticated_predecessor_boots.len() > MAXIMUM_GIT_JOURNAL_RECORDS
            || authenticated_predecessor_boots
                .iter()
                .any(|digest| digest.as_bytes() == &[0; 32] || *digest == boot)
            || !authenticated_predecessor_boots
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || accepted_records.len() > MAXIMUM_GIT_JOURNAL_RECORDS
            || accepted_checkpoints.len() > MAXIMUM_GIT_JOURNAL_RECORDS
            || accepted_records
                .iter()
                .chain(&accepted_checkpoints)
                .any(|digest| digest.as_bytes() == &[0; 32])
            || !accepted_records.windows(2).all(|pair| pair[0] < pair[1])
            || !accepted_checkpoints
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(GitModelError::InvalidModel);
        }
        let current_boottime =
            GitTrustedBoottimeV1::from_verified_observation(boot, current_boottime)?;
        Ok(Self {
            authority,
            validator: GitTrustedValidatorV1::from_verified_digest(
                validator_attestation,
                accepted_graphs,
                accepted_ancestry,
                accepted_validation_reports,
            )?,
            current_boottime,
            boot_rollover: GitBootRolloverAuthorityV1 {
                attestation: boot_rollover_attestation,
                current: current_boottime.boot(),
                predecessors: authenticated_predecessor_boots,
            },
            accepted_records,
            accepted_checkpoints,
        })
    }

    /// Returns the journal-custody authority commitment.
    #[must_use]
    pub const fn authority(&self) -> ObjectDigest {
        self.authority
    }

    /// Returns the verifier-issued graph-validator brand.
    #[must_use]
    pub const fn validator(&self) -> &GitTrustedValidatorV1 {
        &self.validator
    }

    /// Returns the verifier-owned current boot-time observation.
    #[must_use]
    pub const fn current_boottime(&self) -> GitTrustedBoottimeV1 {
        self.current_boottime
    }

    /// Returns the verifier-issued cross-boot reconciliation capability.
    #[must_use]
    pub const fn boot_rollover(&self) -> &GitBootRolloverAuthorityV1 {
        &self.boot_rollover
    }

    pub(super) fn accepts_record(&self, digest: ObjectDigest) -> bool {
        self.accepted_records.binary_search(&digest).is_ok()
    }

    pub(super) fn accepts_checkpoint(&self, digest: ObjectDigest) -> bool {
        self.accepted_checkpoints.binary_search(&digest).is_ok()
    }

    /// Verifies the complete custody set and binds each record to exact bytes.
    ///
    /// Each input pair is `(canonical custody record, exact projection bytes)`.
    /// The returned capability is opaque and consumed by projection replay.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] for malformed custody, missing, duplicate, or
    /// extra records, payload commitment mismatch, checkpoints in a suffix, or
    /// payloads beyond the reconstructing durable-record ceiling.
    pub fn accept_record_set(
        &self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<GitAcceptedRecordSetV1, GitModelError> {
        if entries.len() != self.accepted_records.len()
            || entries.len() > MAXIMUM_GIT_JOURNAL_RECORDS
        {
            return Err(GitModelError::InvalidModel);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(entries.len())
            .map_err(|_| GitModelError::Allocation)?;
        for (custody, payload) in entries {
            if payload.len() > MAXIMUM_GIT_CUSTODIED_PAYLOAD_BYTES {
                return Err(GitModelError::InvalidModel);
            }
            let ownership = decode_git_journal_record_v1(&custody, self)?;
            if ownership.kind == GitJournalRecordKindV1::Checkpoint
                || ownership.record != git_custodied_payload_digest_v1(ownership.kind, &payload)
            {
                return Err(GitModelError::InvalidModel);
            }
            records.push(GitAcceptedRecordV1 {
                ownership,
                custody_digest: ownership.complete_digest(),
                payload,
            });
        }
        let mut actual = Vec::new();
        actual
            .try_reserve_exact(records.len())
            .map_err(|_| GitModelError::Allocation)?;
        actual.extend(records.iter().map(|record| record.custody_digest));
        actual.sort_unstable();
        if !actual.windows(2).all(|pair| pair[0] < pair[1]) || actual != self.accepted_records {
            return Err(GitModelError::InvalidModel);
        }
        Ok(GitAcceptedRecordSetV1 {
            authority: self.authority,
            root: git_accepted_set_root(&records),
            records,
        })
    }
}

impl GitBootRolloverAuthorityV1 {
    /// Returns the verifier's opaque boot-rollover attestation commitment.
    #[must_use]
    pub const fn attestation(&self) -> ObjectDigest {
        self.attestation
    }

    /// Returns the current authenticated boot.
    #[must_use]
    pub const fn current(&self) -> super::GitBootIdV1 {
        self.current
    }

    pub(crate) fn predecessor_boots(&self) -> &[ObjectDigest] {
        &self.predecessors
    }

    pub(super) fn accepts_predecessor(&self, boot: super::GitBootIdV1) -> bool {
        self.predecessors.binary_search(&boot.digest()).is_ok()
    }

    pub(super) fn authenticates(&self, boot: super::GitBootIdV1) -> bool {
        boot == self.current || self.accepts_predecessor(boot)
    }

    fn accepts_record_boot(&self, boot: ObjectDigest) -> bool {
        boot == self.current.digest() || self.predecessors.binary_search(&boot).is_ok()
    }
}

impl GitAcceptedRecordV1 {
    pub(super) const fn ownership(&self) -> GitJournalOwnershipRecordV1 {
        self.ownership
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl GitAcceptedRecordSetV1 {
    /// Returns the exact verifier-bound suffix root.
    #[must_use]
    pub const fn root(&self) -> ObjectDigest {
        self.root
    }

    /// Consumes an exact one-record accepted set for a custody append.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless the set contains exactly
    /// one verifier-accepted record.
    pub fn into_single(self) -> Result<GitAcceptedRecordV1, GitModelError> {
        if self.records.len() != 1 || self.root != git_accepted_set_root(&self.records) {
            return Err(GitModelError::InvalidModel);
        }
        self.records
            .into_iter()
            .next()
            .ok_or(GitModelError::InvalidModel)
    }

    pub(super) fn into_projection(
        self,
        authority: ObjectDigest,
    ) -> Result<Vec<GitAcceptedRecordV1>, GitModelError> {
        if self.authority != authority
            || self
                .records
                .iter()
                .any(|record| record.ownership.kind == GitJournalRecordKindV1::Checkpoint)
            || self.root != git_accepted_set_root(&self.records)
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(self.records)
    }
}

/// Replays exact Git journal ownership lineages without append authority.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GitJournalHistoryV1 {
    latest: BTreeMap<
        (ProjectId, ResourceId, ResourceId, GitJournalRecordKindV1),
        GitJournalOwnershipRecordV1,
    >,
    retained_records: usize,
}

impl GitJournalHistoryV1 {
    /// Replays canonical custody records under one verified journal boundary.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] for corrupt bytes, divergent verifier identity,
    /// a forked lineage, or the fixed retained-record ceiling.
    pub fn replay(
        records: GitAcceptedRecordSetV1,
        verifier: &GitJournalVerifierV1,
    ) -> Result<Self, GitModelError> {
        let mut history = Self::default();
        for record in records.into_projection(verifier.authority())? {
            history.append(record, verifier)?;
        }
        Ok(history)
    }

    /// Appends one already verified custody record to its exact lineage.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a skipped, forked,
    /// duplicate, or over-capacity append.
    pub fn append(
        &mut self,
        accepted: GitAcceptedRecordV1,
        verifier: &GitJournalVerifierV1,
    ) -> Result<(), GitModelError> {
        let record = accepted.ownership;
        if accepted.custody_digest != record.complete_digest()
            || record.record != git_custodied_payload_digest_v1(record.kind, &accepted.payload)
        {
            return Err(GitModelError::InvalidModel);
        }
        let key = (
            record.project,
            record.repository,
            record.namespace,
            record.kind,
        );
        if record.journal_authority != verifier.authority
            || record.validator_authority != verifier.validator.attestation().digest()
            || !verifier
                .boot_rollover
                .accepts_record_boot(record.boot_authority)
            || self.retained_records >= MAXIMUM_GIT_JOURNAL_RECORDS
        {
            return Err(GitModelError::InvalidModel);
        }
        match self.latest.get(&key) {
            Some(previous)
                if previous
                    .revision
                    .checked_next()
                    .is_ok_and(|revision| revision == record.revision)
                    && record.predecessor == Some(previous.complete_digest()) => {}
            None if record.revision.get() == 1 && record.predecessor.is_none() => {}
            _ => return Err(GitModelError::InvalidModel),
        }
        self.latest.insert(key, record);
        self.retained_records += 1;
        Ok(())
    }
}

/// Commits exact durable Git bytes under their closed custody family.
#[must_use]
pub fn git_custodied_payload_digest_v1(
    kind: GitJournalRecordKindV1,
    payload: &[u8],
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.custodied-payload.v1\0")
            .chain_update([kind as u8])
            .chain_update((payload.len() as u64).to_be_bytes())
            .chain_update(payload)
            .finalize()
            .into(),
    )
}

fn git_accepted_set_root(records: &[GitAcceptedRecordV1]) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.accepted-record-set.v1\0")
        .chain_update((records.len() as u64).to_be_bytes());
    for record in records {
        hasher = hasher
            .chain_update(record.custody_digest.as_bytes())
            .chain_update(record.ownership.record.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Encodes one fixed-size Git journal custody record.
///
/// # Errors
///
/// Returns [`GitModelError::Allocation`] if checked allocation fails.
pub fn encode_git_journal_record_v1(
    record: GitJournalOwnershipRecordV1,
) -> Result<Vec<u8>, GitModelError> {
    let body = encode_body(record);
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(RECORD_BYTES)
        .map_err(|_| GitModelError::Allocation)?;
    encoded.extend_from_slice(&body);
    encoded.extend_from_slice(journal_digest(&body).as_bytes());
    Ok(encoded)
}

/// Decodes one fixed-size verifier-bound Git journal custody record.
///
/// # Errors
///
/// Returns [`GitModelError::CorruptEncoding`] for malformed bytes or a
/// validator authority different from the supplied verifier.
pub fn decode_git_journal_record_v1(
    encoded: &[u8],
    verifier: &GitJournalVerifierV1,
) -> Result<GitJournalOwnershipRecordV1, GitModelError> {
    if encoded.len() != RECORD_BYTES {
        return Err(GitModelError::CorruptEncoding);
    }
    let (body, stored) = encoded.split_at(BODY_BYTES);
    let digest = journal_digest(body);
    if digest.as_bytes() != stored || !verifier.accepts_record(digest) {
        return Err(GitModelError::CorruptEncoding);
    }
    let mut bytes = body;
    if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
        return Err(GitModelError::CorruptEncoding);
    }
    let kind = match take::<1>(&mut bytes)?[0] {
        1 => GitJournalRecordKindV1::State,
        2 => GitJournalRecordKindV1::ReceiveEffect,
        3 => GitJournalRecordKindV1::Checkpoint,
        _ => return Err(GitModelError::CorruptEncoding),
    };
    if take::<5>(&mut bytes)? != [0; 5] {
        return Err(GitModelError::CorruptEncoding);
    }
    let record = GitJournalOwnershipRecordV1::new(
        kind,
        ProjectId::from_bytes(take(&mut bytes)?),
        ResourceId::from_bytes(take(&mut bytes)?),
        ResourceId::from_bytes(take(&mut bytes)?),
        Revision::new(u64::from_be_bytes(take(&mut bytes)?)),
        optional_digest(take(&mut bytes)?),
        ObjectDigest::from_bytes(take(&mut bytes)?),
        ObjectDigest::from_bytes(take(&mut bytes)?),
        ObjectDigest::from_bytes(take(&mut bytes)?),
        ObjectDigest::from_bytes(take(&mut bytes)?),
        optional_revision(u64::from_be_bytes(take(&mut bytes)?)),
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    if record.journal_authority != verifier.authority
        || record.validator_authority != verifier.validator.attestation().digest()
        || !verifier
            .boot_rollover
            .accepts_record_boot(record.boot_authority)
    {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(record)
}

fn encode_body(record: GitJournalOwnershipRecordV1) -> [u8; BODY_BYTES] {
    let mut bytes = [0_u8; BODY_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = record.kind as u8;
    bytes[16..32].copy_from_slice(record.project.as_bytes());
    bytes[32..48].copy_from_slice(record.repository.as_bytes());
    bytes[48..64].copy_from_slice(record.namespace.as_bytes());
    bytes[64..72].copy_from_slice(&record.revision.get().to_be_bytes());
    bytes[72..104].copy_from_slice(
        record
            .predecessor
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    bytes[104..136].copy_from_slice(record.record.as_bytes());
    bytes[136..168].copy_from_slice(record.journal_authority.as_bytes());
    bytes[168..200].copy_from_slice(record.validator_authority.as_bytes());
    bytes[200..232].copy_from_slice(record.boot_authority.as_bytes());
    bytes[232..240].copy_from_slice(&record.replay_floor.map_or(0, Revision::get).to_be_bytes());
    bytes
}

fn journal_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.journal-custody.v1\0")
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn optional_digest(bytes: [u8; 32]) -> Option<ObjectDigest> {
    (bytes != [0; 32]).then_some(ObjectDigest::from_bytes(bytes))
}

fn optional_revision(value: u64) -> Option<Revision> {
    (value != 0).then_some(Revision::new(value))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], GitModelError> {
    let (head, tail) = bytes
        .split_at_checked(N)
        .ok_or(GitModelError::CorruptEncoding)?;
    *bytes = tail;
    head.try_into().map_err(|_| GitModelError::CorruptEncoding)
}
