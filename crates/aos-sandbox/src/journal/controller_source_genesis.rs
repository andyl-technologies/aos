//! Controller bootstrap custody through Root floor and actual Source ACK.
//!
//! ```text
//! DesiredState[acceptance-prefix || project] = AOSSGC01[608]
//! DesiredState[floor-ack-prefix || project] =
//! AOSSGA01 | version:u16=1 | reserved[6] | acceptance[32] |
//! Root-floor[32] | Source-receipt[32] | checksum[32]
//! DesiredState[complete-prefix || project] =
//! AOSSGD01 | version:u16=1 | reserved[6] | floor-ACK[32] |
//! Source-ACK[32] | Root-floor[32] | checksum[32]
//! ```
//!
//! The immutable acceptance is not administrative issuance or Root authority.
//! Until the actual Source ACK is durably accepted, this bootstrap fences all
//! Controller mutation and compaction. Generic writes cannot fabricate any of
//! these rows; only the held genesis consumer invokes the internal transitions.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, ProjectId};

use super::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};
use crate::hierarchy::genesis_profile::{
    ControllerSourceGenesisAcceptanceRecordV1, SourceGenesisErrorV1, digest_at, hash, take,
};

pub(crate) const ACCEPTANCE_PREFIX: &[u8] = b"\0aos-controller-source-genesis-acceptance-v1\0";
const ACK_PREFIX: &[u8] = b"\0aos-controller-source-genesis-floor-ack-v1\0";
const COMPLETE_PREFIX: &[u8] = b"\0aos-controller-source-genesis-complete-v1\0";
const ACK_MAGIC: &[u8; 8] = b"AOSSGA01";
const COMPLETE_MAGIC: &[u8; 8] = b"AOSSGD01";
const ACK_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.controller-floor-ack.v1\0";
const COMPLETE_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.controller-complete.v1\0";
const MAXIMUM_PROJECTS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerSourceGenesisTransition {
    None,
    Accept,
    FloorAck,
    Complete,
}

#[derive(Clone, Debug)]
pub(crate) struct ControllerSourceGenesisRowsV1 {
    pub(crate) acceptance: ControllerSourceGenesisAcceptanceRecordV1,
    pub(crate) ack: Option<[u8; 144]>,
    pub(crate) complete: Option<[u8; 144]>,
}

pub(crate) fn project_key(prefix: &[u8], project: ProjectId) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(project.as_bytes());
    key
}

pub(crate) fn rows(
    journal: &Journal,
    project: ProjectId,
) -> Result<Option<ControllerSourceGenesisRowsV1>, SourceGenesisErrorV1> {
    let validated = all_rows(&journal.state).map_err(SourceGenesisErrorV1::from)?;
    Ok(validated.get(&project).cloned())
}

pub(crate) fn pending(
    journal: &Journal,
) -> Result<Option<ControllerSourceGenesisAcceptanceRecordV1>, SourceGenesisErrorV1> {
    let validated = all_rows(&journal.state)?;
    Ok(validated
        .into_values()
        .find(|row| row.complete.is_none())
        .map(|row| row.acceptance))
}

pub(crate) fn ack_bytes(
    acceptance: ObjectDigest,
    floor: ObjectDigest,
    receipt: ObjectDigest,
) -> Result<[u8; 144], SourceGenesisErrorV1> {
    joined_bytes(ACK_MAGIC, ACK_DOMAIN, [acceptance, floor, receipt])
}

pub(crate) fn complete_bytes(
    ack: &[u8; 144],
    source_ack: ObjectDigest,
    floor: ObjectDigest,
) -> Result<[u8; 144], SourceGenesisErrorV1> {
    joined_bytes(
        COMPLETE_MAGIC,
        COMPLETE_DOMAIN,
        [hash(ACK_DOMAIN, ack), source_ack, floor],
    )
}

pub(crate) fn ack_digest(bytes: &[u8; 144]) -> ObjectDigest {
    hash(ACK_DOMAIN, bytes)
}

pub(crate) fn acceptance_transaction(
    record: &ControllerSourceGenesisAcceptanceRecordV1,
) -> Result<JournalTransaction, JournalError> {
    transaction(
        b"accept",
        record.digest(),
        JournalRecord::put(
            RecordNamespace::DesiredState,
            project_key(ACCEPTANCE_PREFIX, record.project()),
            record.record_bytes().to_vec(),
        ),
    )
}

pub(crate) fn ack_transaction(
    project: ProjectId,
    bytes: &[u8; 144],
) -> Result<JournalTransaction, JournalError> {
    transaction(
        b"floor-ack",
        hash(ACK_DOMAIN, bytes),
        JournalRecord::put(
            RecordNamespace::DesiredState,
            project_key(ACK_PREFIX, project),
            bytes.to_vec(),
        ),
    )
}

pub(crate) fn complete_transaction(
    project: ProjectId,
    bytes: &[u8; 144],
) -> Result<JournalTransaction, JournalError> {
    transaction(
        b"complete",
        hash(COMPLETE_DOMAIN, bytes),
        JournalRecord::put(
            RecordNamespace::DesiredState,
            project_key(COMPLETE_PREFIX, project),
            bytes.to_vec(),
        ),
    )
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: ControllerSourceGenesisTransition,
) -> Result<(), JournalError> {
    let current = all_rows(state)?;
    let pending = current.values().find(|row| row.complete.is_none());
    let owned = transaction
        .records()
        .iter()
        .any(|record| owned_key(record.namespace(), record.key()));
    if transition == ControllerSourceGenesisTransition::None {
        return if owned || pending.is_some() {
            Err(JournalError::ProtectedBoundary)
        } else {
            Ok(())
        };
    }
    if transaction.records().len() != 1 || !owned {
        return Err(JournalError::ProtectedBoundary);
    }
    let record = &transaction.records()[0];
    let mut successor = state.clone();
    let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
    if successor
        .insert((record.namespace(), record.key().to_vec()), value.to_vec())
        .is_some()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let after = all_rows(&successor)?;
    match transition {
        ControllerSourceGenesisTransition::Accept => {
            if pending.is_some()
                || !record.key().starts_with(ACCEPTANCE_PREFIX)
                || after.len() != current.len() + 1
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        ControllerSourceGenesisTransition::FloorAck => {
            let prior = pending.ok_or(JournalError::ProtectedBoundary)?;
            if prior.ack.is_some()
                || record.key() != project_key(ACK_PREFIX, prior.acceptance.project())
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        ControllerSourceGenesisTransition::Complete => {
            let prior = pending.ok_or(JournalError::ProtectedBoundary)?;
            if prior.ack.is_none()
                || record.key() != project_key(COMPLETE_PREFIX, prior.acceptance.project())
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        ControllerSourceGenesisTransition::None => return Err(JournalError::ProtectedBoundary),
    }
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if all_rows(state)?.values().any(|row| row.complete.is_none()) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn all_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<BTreeMap<ProjectId, ControllerSourceGenesisRowsV1>, JournalError> {
    let mut accepted = BTreeMap::new();
    let mut acknowledgments = BTreeMap::new();
    let mut completions = BTreeMap::new();
    for ((namespace, key), value) in state {
        if !owned_key(*namespace, key) {
            continue;
        }
        let (prefix, family) = if key.starts_with(ACCEPTANCE_PREFIX) {
            (ACCEPTANCE_PREFIX, 0)
        } else if key.starts_with(ACK_PREFIX) {
            (ACK_PREFIX, 1)
        } else {
            (COMPLETE_PREFIX, 2)
        };
        let project = ProjectId::from_bytes(
            take(key, prefix.len()).map_err(|_| JournalError::ProtectedBoundary)?,
        );
        if key.len() != prefix.len() + 16 || project.as_bytes() == &[0; 16] {
            return Err(JournalError::ProtectedBoundary);
        }
        if family == 0 {
            let acceptance = ControllerSourceGenesisAcceptanceRecordV1::from_record_bytes(value)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if acceptance.project() != project {
                return Err(JournalError::ProtectedBoundary);
            }
            accepted.insert(
                project,
                ControllerSourceGenesisRowsV1 {
                    acceptance,
                    ack: None,
                    complete: None,
                },
            );
        } else {
            let (magic, domain) = if family == 1 {
                (ACK_MAGIC, ACK_DOMAIN)
            } else {
                (COMPLETE_MAGIC, COMPLETE_DOMAIN)
            };
            let bytes = validate_joined(value, magic, domain)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if family == 1 {
                acknowledgments.insert(project, bytes);
            } else {
                completions.insert(project, bytes);
            }
        }
    }
    for (project, ack) in acknowledgments {
        let row = accepted
            .get_mut(&project)
            .ok_or(JournalError::ProtectedBoundary)?;
        if digest_at(&ack, 16) != row.acceptance.digest() {
            return Err(JournalError::ProtectedBoundary);
        }
        row.ack = Some(ack);
    }
    for (project, complete) in completions {
        let row = accepted
            .get_mut(&project)
            .ok_or(JournalError::ProtectedBoundary)?;
        let ack = row.ack.ok_or(JournalError::ProtectedBoundary)?;
        if digest_at(&complete, 16) != ack_digest(&ack)
            || digest_at(&complete, 80) != digest_at(&ack, 48)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        row.complete = Some(complete);
    }
    if accepted.len() > MAXIMUM_PROJECTS
        || accepted
            .values()
            .filter(|row| row.complete.is_none())
            .count()
            > 1
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(accepted)
}

fn owned_key(namespace: RecordNamespace, key: &[u8]) -> bool {
    namespace == RecordNamespace::DesiredState
        && [ACCEPTANCE_PREFIX, ACK_PREFIX, COMPLETE_PREFIX]
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

fn joined_bytes(
    magic: &[u8; 8],
    domain: &[u8],
    joins: [ObjectDigest; 3],
) -> Result<[u8; 144], SourceGenesisErrorV1> {
    if joins.iter().any(|digest| digest.as_bytes() == &[0; 32]) {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let mut bytes = [0; 144];
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    for (index, join) in joins.into_iter().enumerate() {
        bytes[16 + index * 32..48 + index * 32].copy_from_slice(join.as_bytes());
    }
    let checksum = hash(domain, &bytes[..112]);
    bytes[112..].copy_from_slice(checksum.as_bytes());
    Ok(bytes)
}

fn validate_joined(
    bytes: &[u8],
    magic: &[u8; 8],
    domain: &[u8],
) -> Result<[u8; 144], SourceGenesisErrorV1> {
    if bytes.len() != 144
        || bytes.get(..8) != Some(magic.as_slice())
        || bytes[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let expected = joined_bytes(
        magic,
        domain,
        [
            digest_at(bytes, 16),
            digest_at(bytes, 48),
            digest_at(bytes, 80),
        ],
    )?;
    if expected.as_slice() != bytes {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(expected)
}

fn transaction(
    kind: &[u8],
    digest: ObjectDigest,
    record: JournalRecord,
) -> Result<JournalTransaction, JournalError> {
    let digest = hash(
        b"aos.sandbox.source-genesis.controller-transaction.v1\0",
        &[kind, digest.as_bytes()].concat(),
    );
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    JournalTransaction::new(id, vec![record])
}
