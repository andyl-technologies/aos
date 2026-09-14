//! Inert environment journal namespace ownership model.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId, Revision, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{EnvironmentLeaseTimeV1, EnvironmentModelError, EnvironmentTrustedTimeV1};

const MAGIC: &[u8; 8] = b"AOSENVJ1";
const VERSION: u16 = 1;
const BODY_BYTES: usize = 208;
const RECORD_BYTES: usize = BODY_BYTES + 32;
const MAXIMUM_ENVIRONMENT_JOURNAL_RECORDS: usize = 262_144;
const MAXIMUM_ENVIRONMENT_CUSTODIED_PAYLOAD_BYTES: usize = 96 * 1024 * 1024;

/// Identifies the dormant environment journal namespace format.
pub const ENVIRONMENT_JOURNAL_NAMESPACE_V1: &str = "aos.sandbox.environment.v1";

/// Selects one environment journal projection.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EnvironmentJournalRecordKindV1 {
    /// Stores an immutable generation manifest.
    Generation = 1,
    /// Stores an activation-transaction revision.
    Activation = 2,
    /// Stores a materialized compaction checkpoint.
    Checkpoint = 3,
}

impl EnvironmentJournalRecordKindV1 {
    /// Maps this dormant record kind to the existing shared-journal namespace.
    #[must_use]
    pub const fn record_namespace(self) -> crate::journal::RecordNamespace {
        match self {
            Self::Generation | Self::Activation => crate::journal::RecordNamespace::DesiredState,
            Self::Checkpoint => crate::journal::RecordNamespace::RuntimeGeneration,
        }
    }
}

/// Returns the shared-journal namespace used for immutable environment state.
#[must_use]
pub const fn environment_record_namespace_v1() -> crate::journal::RecordNamespace {
    EnvironmentJournalRecordKindV1::Generation.record_namespace()
}

/// Binds one environment record to an isolated project/sandbox namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvironmentJournalOwnershipRecordV1 {
    kind: EnvironmentJournalRecordKindV1,
    project: ProjectId,
    sandbox: SandboxId,
    namespace: ResourceId,
    revision: Revision,
    predecessor: Option<ObjectDigest>,
    record: ObjectDigest,
    journal_authority: ObjectDigest,
    boot_authority: ObjectDigest,
    replay_floor: Option<Revision>,
}

impl EnvironmentJournalOwnershipRecordV1 {
    /// Constructs one dormant journal ownership record.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for sentinel fields,
    /// broken first-record shape, or a replay floor above the record revision.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: EnvironmentJournalRecordKindV1,
        project: ProjectId,
        sandbox: SandboxId,
        namespace: ResourceId,
        revision: Revision,
        predecessor: Option<ObjectDigest>,
        record: ObjectDigest,
        journal_authority: ObjectDigest,
        boot_authority: ObjectDigest,
        replay_floor: Option<Revision>,
    ) -> Result<Self, EnvironmentModelError> {
        if project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || namespace.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
            || record.as_bytes() == &[0; 32]
            || journal_authority.as_bytes() == &[0; 32]
            || boot_authority.as_bytes() == &[0; 32]
            || (revision.get() == 1) != predecessor.is_none()
            || replay_floor.is_some_and(|floor| floor.get() == 0 || floor.get() > revision.get())
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(Self {
            kind,
            project,
            sandbox,
            namespace,
            revision,
            predecessor,
            record,
            journal_authority,
            boot_authority,
            replay_floor,
        })
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }
    /// Returns the owning sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }
    /// Returns the isolated namespace identity.
    #[must_use]
    pub const fn namespace(self) -> ResourceId {
        self.namespace
    }
    /// Returns the exact environment record family.
    #[must_use]
    pub const fn kind(self) -> EnvironmentJournalRecordKindV1 {
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
    /// Returns the verifier-owned journal-custody authority commitment.
    #[must_use]
    pub const fn journal_authority(self) -> ObjectDigest {
        self.journal_authority
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

    /// Returns the canonical complete ownership-record commitment.
    #[must_use]
    pub fn complete_digest(self) -> ObjectDigest {
        journal_digest(&encode_body(self))
    }
}

/// Carries trusted dormant environment-journal verification state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentJournalVerifierV1 {
    authority: ObjectDigest,
    current_time: EnvironmentTrustedTimeV1,
    boot_rollover: EnvironmentBootRolloverAuthorityV1,
    accepted_records: Vec<ObjectDigest>,
    accepted_checkpoints: Vec<ObjectDigest>,
}

/// Proves which authenticated predecessor boots may be reconciled into the
/// verifier's current boot.
///
/// Only the journal verifier can issue this opaque capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentBootRolloverAuthorityV1 {
    attestation: ObjectDigest,
    current: super::EnvironmentBootIdV1,
    predecessors: Vec<ObjectDigest>,
}

/// Carries one verifier-accepted custody record and its exact domain bytes.
///
/// Its fields are private so arbitrary payload bytes cannot be relabeled as
/// journal-custodied state without passing [`EnvironmentJournalVerifierV1`].
#[derive(Debug, Eq, PartialEq)]
pub struct EnvironmentAcceptedRecordV1 {
    ownership: EnvironmentJournalOwnershipRecordV1,
    custody_digest: ObjectDigest,
    payload: Vec<u8>,
}

/// Carries the exact complete accepted custody set for one replay suffix.
///
/// Replay consumes this value. The verifier rejects both omitted accepted
/// custody records and caller-supplied extras before issuing it.
#[derive(Debug, Eq, PartialEq)]
pub struct EnvironmentAcceptedRecordSetV1 {
    authority: ObjectDigest,
    root: ObjectDigest,
    records: Vec<EnvironmentAcceptedRecordV1>,
}

impl EnvironmentJournalVerifierV1 {
    pub(crate) fn from_verified_state(
        authority: ObjectDigest,
        boot: ObjectDigest,
        current_time: EnvironmentLeaseTimeV1,
        boot_rollover_attestation: ObjectDigest,
        authenticated_predecessor_boots: Vec<ObjectDigest>,
        accepted_records: Vec<ObjectDigest>,
        accepted_checkpoints: Vec<ObjectDigest>,
    ) -> Result<Self, EnvironmentModelError> {
        if authority.as_bytes() == &[0; 32]
            || boot_rollover_attestation.as_bytes() == &[0; 32]
            || authenticated_predecessor_boots.len() > MAXIMUM_ENVIRONMENT_JOURNAL_RECORDS
            || authenticated_predecessor_boots
                .iter()
                .any(|digest| digest.as_bytes() == &[0; 32] || *digest == boot)
            || !authenticated_predecessor_boots
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || accepted_records.len() > MAXIMUM_ENVIRONMENT_JOURNAL_RECORDS
            || accepted_checkpoints.len() > MAXIMUM_ENVIRONMENT_JOURNAL_RECORDS
            || accepted_records
                .iter()
                .chain(&accepted_checkpoints)
                .any(|digest| digest.as_bytes() == &[0; 32])
            || !accepted_records.windows(2).all(|pair| pair[0] < pair[1])
            || !accepted_checkpoints
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        let current_time = EnvironmentTrustedTimeV1::from_verified_observation(boot, current_time)?;
        Ok(Self {
            authority,
            current_time,
            boot_rollover: EnvironmentBootRolloverAuthorityV1 {
                attestation: boot_rollover_attestation,
                current: current_time.boot(),
                predecessors: authenticated_predecessor_boots,
            },
            accepted_records,
            accepted_checkpoints,
        })
    }

    /// Returns the verifier-owned current lease observation.
    #[must_use]
    pub const fn current_time(&self) -> EnvironmentTrustedTimeV1 {
        self.current_time
    }

    /// Returns the journal-custody authority commitment.
    #[must_use]
    pub const fn authority(&self) -> ObjectDigest {
        self.authority
    }

    /// Returns the verifier-issued cross-boot reconciliation capability.
    #[must_use]
    pub const fn boot_rollover(&self) -> &EnvironmentBootRolloverAuthorityV1 {
        &self.boot_rollover
    }

    pub(super) fn accepts_record(&self, digest: ObjectDigest) -> bool {
        self.accepted_records.binary_search(&digest).is_ok()
    }

    pub(super) fn accepts_checkpoint(&self, digest: ObjectDigest) -> bool {
        self.accepted_checkpoints.binary_search(&digest).is_ok()
    }

    /// Verifies and consumes the exact payload-bearing custody suffix.
    ///
    /// Each input pair is `(canonical custody record, exact domain payload)`.
    /// The resulting opaque set contains every and only record named by this
    /// verifier's accepted-record set.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] for malformed custody bytes, a
    /// missing or extra accepted record, duplicate custody, a payload digest
    /// mismatch, a checkpoint record in a suffix, or a payload over its bound.
    pub fn accept_record_set(
        &self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<EnvironmentAcceptedRecordSetV1, EnvironmentModelError> {
        if entries.len() != self.accepted_records.len()
            || entries.len() > MAXIMUM_ENVIRONMENT_JOURNAL_RECORDS
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(entries.len())
            .map_err(|_| EnvironmentModelError::Allocation)?;
        for (custody, payload) in entries {
            if payload.len() > MAXIMUM_ENVIRONMENT_CUSTODIED_PAYLOAD_BYTES {
                return Err(EnvironmentModelError::InvalidModel);
            }
            let ownership = decode_environment_journal_record_v1(&custody, self)?;
            if ownership.kind == EnvironmentJournalRecordKindV1::Checkpoint
                || ownership.record
                    != environment_custodied_payload_digest_v1(ownership.kind, &payload)
            {
                return Err(EnvironmentModelError::InvalidModel);
            }
            records.push(EnvironmentAcceptedRecordV1 {
                ownership,
                custody_digest: ownership.complete_digest(),
                payload,
            });
        }
        let mut actual = Vec::new();
        actual
            .try_reserve_exact(records.len())
            .map_err(|_| EnvironmentModelError::Allocation)?;
        actual.extend(records.iter().map(|record| record.custody_digest));
        actual.sort_unstable();
        if !actual.windows(2).all(|pair| pair[0] < pair[1]) || actual != self.accepted_records {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(EnvironmentAcceptedRecordSetV1 {
            authority: self.authority,
            root: environment_accepted_set_root(&records),
            records,
        })
    }
}

impl EnvironmentBootRolloverAuthorityV1 {
    /// Returns the verifier's opaque boot-rollover attestation commitment.
    #[must_use]
    pub const fn attestation(&self) -> ObjectDigest {
        self.attestation
    }

    /// Returns the current authenticated boot.
    #[must_use]
    pub const fn current(&self) -> super::EnvironmentBootIdV1 {
        self.current
    }

    pub(super) fn accepts_predecessor(&self, boot: super::EnvironmentBootIdV1) -> bool {
        self.predecessors.binary_search(&boot.digest()).is_ok()
    }

    pub(super) fn authenticates(&self, boot: super::EnvironmentBootIdV1) -> bool {
        boot == self.current || self.accepts_predecessor(boot)
    }

    fn accepts_record_boot(&self, boot: ObjectDigest) -> bool {
        boot == self.current.digest() || self.predecessors.binary_search(&boot).is_ok()
    }
}

impl EnvironmentAcceptedRecordV1 {
    pub(super) const fn ownership(&self) -> EnvironmentJournalOwnershipRecordV1 {
        self.ownership
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl EnvironmentAcceptedRecordSetV1 {
    /// Returns the verifier-bound exact suffix root.
    #[must_use]
    pub const fn root(&self) -> ObjectDigest {
        self.root
    }

    /// Consumes an exact one-record accepted set for an append operation.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] unless this set contains
    /// exactly one verifier-accepted custody record.
    pub fn into_single(self) -> Result<EnvironmentAcceptedRecordV1, EnvironmentModelError> {
        if self.records.len() != 1 || self.root != environment_accepted_set_root(&self.records) {
            return Err(EnvironmentModelError::InvalidModel);
        }
        self.records
            .into_iter()
            .next()
            .ok_or(EnvironmentModelError::InvalidModel)
    }

    pub(super) fn into_kind(
        self,
        kind: EnvironmentJournalRecordKindV1,
        authority: Option<ObjectDigest>,
    ) -> Result<Vec<EnvironmentAcceptedRecordV1>, EnvironmentModelError> {
        if self.authority.as_bytes() == &[0; 32]
            || authority.is_some_and(|expected| expected != self.authority)
            || self
                .records
                .iter()
                .any(|record| record.ownership.kind != kind)
            || self.root != environment_accepted_set_root(&self.records)
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(self.records)
    }

    fn into_records(
        self,
        authority: ObjectDigest,
    ) -> Result<Vec<EnvironmentAcceptedRecordV1>, EnvironmentModelError> {
        if self.authority != authority || self.root != environment_accepted_set_root(&self.records)
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(self.records)
    }
}

/// Replays exact environment-journal ownership lineages without I/O authority.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentJournalHistoryV1 {
    latest: BTreeMap<
        (
            ProjectId,
            SandboxId,
            ResourceId,
            EnvironmentJournalRecordKindV1,
        ),
        EnvironmentJournalOwnershipRecordV1,
    >,
    retained_records: usize,
}

impl EnvironmentJournalHistoryV1 {
    /// Replays canonical custody records under one verified journal boundary.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError`] for malformed bytes, a forked lineage,
    /// or the fixed retained-record ceiling.
    pub fn replay(
        records: EnvironmentAcceptedRecordSetV1,
        verifier: &EnvironmentJournalVerifierV1,
    ) -> Result<Self, EnvironmentModelError> {
        let mut history = Self::default();
        for record in records.into_records(verifier.authority())? {
            history.append(record, verifier)?;
        }
        Ok(history)
    }

    /// Appends one already verified namespace record to its exact lineage.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentModelError::InvalidModel`] for a skipped, forked,
    /// duplicate, or over-capacity append.
    pub fn append(
        &mut self,
        accepted: EnvironmentAcceptedRecordV1,
        verifier: &EnvironmentJournalVerifierV1,
    ) -> Result<(), EnvironmentModelError> {
        let record = accepted.ownership;
        if accepted.custody_digest != record.complete_digest()
            || record.record
                != environment_custodied_payload_digest_v1(record.kind, &accepted.payload)
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        let key = (
            record.project,
            record.sandbox,
            record.namespace,
            record.kind,
        );
        if record.journal_authority != verifier.authority
            || !verifier
                .boot_rollover
                .accepts_record_boot(record.boot_authority)
            || self.retained_records >= MAXIMUM_ENVIRONMENT_JOURNAL_RECORDS
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        match self.latest.get(&key) {
            Some(previous)
                if previous
                    .revision
                    .checked_next()
                    .is_ok_and(|revision| revision == record.revision)
                    && record.predecessor == Some(previous.complete_digest()) => {}
            None if record.revision.get() == 1 && record.predecessor.is_none() => {}
            _ => return Err(EnvironmentModelError::InvalidModel),
        }
        self.latest.insert(key, record);
        self.retained_records += 1;
        Ok(())
    }
}

/// Commits one exact environment projection payload under its closed family.
#[must_use]
pub fn environment_custodied_payload_digest_v1(
    kind: EnvironmentJournalRecordKindV1,
    payload: &[u8],
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.environment.custodied-payload.v1\0")
            .chain_update([kind as u8])
            .chain_update((payload.len() as u64).to_be_bytes())
            .chain_update(payload)
            .finalize()
            .into(),
    )
}

fn environment_accepted_set_root(records: &[EnvironmentAcceptedRecordV1]) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.environment.accepted-record-set.v1\0")
        .chain_update((records.len() as u64).to_be_bytes());
    for record in records {
        hasher = hasher
            .chain_update(record.custody_digest.as_bytes())
            .chain_update(record.ownership.record.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Encodes one fixed-size environment journal custody record.
///
/// # Errors
///
/// Returns [`EnvironmentModelError::Allocation`] if checked allocation fails.
pub fn encode_environment_journal_record_v1(
    record: EnvironmentJournalOwnershipRecordV1,
) -> Result<Vec<u8>, EnvironmentModelError> {
    let body = encode_body(record);
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(RECORD_BYTES)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    encoded.extend_from_slice(&body);
    encoded.extend_from_slice(journal_digest(&body).as_bytes());
    Ok(encoded)
}

/// Decodes one fixed-size environment journal custody record.
///
/// # Errors
///
/// Returns [`EnvironmentModelError::CorruptEncoding`] for malformed bytes or
/// a record outside the supplied verifier's journal custody.
pub fn decode_environment_journal_record_v1(
    encoded: &[u8],
    verifier: &EnvironmentJournalVerifierV1,
) -> Result<EnvironmentJournalOwnershipRecordV1, EnvironmentModelError> {
    if encoded.len() != RECORD_BYTES {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let (body, stored) = encoded.split_at(BODY_BYTES);
    let digest = journal_digest(body);
    if digest.as_bytes() != stored || !verifier.accepts_record(digest) {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let mut bytes = body;
    if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let kind = match take::<1>(&mut bytes)?[0] {
        1 => EnvironmentJournalRecordKindV1::Generation,
        2 => EnvironmentJournalRecordKindV1::Activation,
        3 => EnvironmentJournalRecordKindV1::Checkpoint,
        _ => return Err(EnvironmentModelError::CorruptEncoding),
    };
    if take::<5>(&mut bytes)? != [0; 5] {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    EnvironmentJournalOwnershipRecordV1::new(
        kind,
        ProjectId::from_bytes(take(&mut bytes)?),
        SandboxId::from_bytes(take(&mut bytes)?),
        ResourceId::from_bytes(take(&mut bytes)?),
        Revision::new(u64::from_be_bytes(take(&mut bytes)?)),
        optional_digest(take(&mut bytes)?),
        ObjectDigest::from_bytes(take(&mut bytes)?),
        ObjectDigest::from_bytes(take(&mut bytes)?),
        ObjectDigest::from_bytes(take(&mut bytes)?),
        optional_revision(u64::from_be_bytes(take(&mut bytes)?)),
    )
    .map_err(|_| EnvironmentModelError::CorruptEncoding)
    .and_then(|record| {
        (record.journal_authority == verifier.authority
            && verifier
                .boot_rollover
                .accepts_record_boot(record.boot_authority))
        .then_some(record)
        .ok_or(EnvironmentModelError::CorruptEncoding)
    })
}

fn encode_body(record: EnvironmentJournalOwnershipRecordV1) -> [u8; BODY_BYTES] {
    let mut bytes = [0_u8; BODY_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = record.kind as u8;
    bytes[16..32].copy_from_slice(record.project.as_bytes());
    bytes[32..48].copy_from_slice(record.sandbox.as_bytes());
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
    bytes[168..200].copy_from_slice(record.boot_authority.as_bytes());
    bytes[200..208].copy_from_slice(&record.replay_floor.map_or(0, Revision::get).to_be_bytes());
    bytes
}

fn journal_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.environment.journal-custody.v1\0")
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

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], EnvironmentModelError> {
    let (head, tail) = bytes
        .split_at_checked(N)
        .ok_or(EnvironmentModelError::CorruptEncoding)?;
    *bytes = tail;
    head.try_into()
        .map_err(|_| EnvironmentModelError::CorruptEncoding)
}
