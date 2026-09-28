//! Bounded Source genesis rows and the exact pending-floor mutation fence.
//!
//! Receipt bytes are immutable data. Only the genuine Source owner may use
//! the private append/anchor transitions after rechecking live Controller and
//! Root borrows. Ordinary appends cannot write these keys, and a pending row
//! excludes every unrelated mutation and compaction, including after reopen.
//!
//! ```text
//! pending = AOSSGP01 | version:u16be | reserved[6]=0 | instance[32] |
//! project[16] | Root-intent[32] | receipt[32] | Root-nonce[16] |
//! fixed directory/journal/lock(device,inode)[48] | checksum[32]
//! ACK = AOSSGA01 | version:u16be | reserved[6]=0 | instance[32] |
//! project[16] | receipt[32] | Root-floor[32] | Controller-floor[32] |
//! checksum[32]
//! ```

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{
    Journal, JournalError, JournalRecord, JournalTransaction, ProtectedJournalNamesV1,
    RecordNamespace,
};
use crate::hierarchy::protected_journal::{
    HierarchyProtectedJournalKeyV1, HierarchyProtectedRecordKindV1,
};
use crate::hierarchy::source_genesis::SourceTreeGenesisReceiptV1;

pub(crate) const PENDING_KEY: &[u8] = b"\0aos-source-tree-genesis-pending-v1\0";
const KEY_FAMILY_PREFIX: &[u8] = b"\0aos-source-tree-genesis-";
const RECEIPT_PREFIX: &[u8] = b"\0aos-source-tree-genesis-receipt-v1\0";
const ACK_PREFIX: &[u8] = b"\0aos-source-tree-genesis-ack-v1\0";
const PENDING_BYTES: usize = 224;
const ACK_BYTES: usize = 192;
const PENDING_DOMAIN: &[u8] = b"aos.sandbox.source-tree-genesis.pending.v1\0";
const ACK_DOMAIN: &[u8] = b"aos.sandbox.source-tree-genesis.ack.v1\0";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SourceGenesisTransitionV1 {
    None,
    Append,
    Anchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceGenesisPendingV1 {
    pub(crate) instance: [u8; 32],
    pub(crate) project: ProjectId,
    pub(crate) intent: ObjectDigest,
    pub(crate) receipt: ObjectDigest,
    pub(crate) nonce: [u8; 16],
    pub(crate) names: ProtectedJournalNamesV1,
}

impl SourceGenesisPendingV1 {
    pub(crate) fn encode(&self) -> [u8; PENDING_BYTES] {
        let mut bytes = [0; PENDING_BYTES];
        bytes[..8].copy_from_slice(b"AOSSGP01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.instance);
        bytes[48..64].copy_from_slice(self.project.as_bytes());
        bytes[64..96].copy_from_slice(self.intent.as_bytes());
        bytes[96..128].copy_from_slice(self.receipt.as_bytes());
        bytes[128..144].copy_from_slice(&self.nonce);
        bytes[144..192].copy_from_slice(&self.names.to_bytes());
        let digest = checksum(PENDING_DOMAIN, &bytes[..192]);
        bytes[192..].copy_from_slice(digest.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        require_frame(bytes, b"AOSSGP01", PENDING_BYTES, PENDING_DOMAIN)?;
        let value = Self {
            instance: array(bytes, 16)?,
            project: ProjectId::from_bytes(array(bytes, 48)?),
            intent: ObjectDigest::from_bytes(array(bytes, 64)?),
            receipt: ObjectDigest::from_bytes(array(bytes, 96)?),
            nonce: array(bytes, 128)?,
            names: ProtectedJournalNamesV1::from_bytes(&bytes[144..192])?,
        };
        if value.nonce == [0; 16]
            || value.intent.as_bytes() == &[0; 32]
            || value.receipt.as_bytes() == &[0; 32]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceGenesisAckV1 {
    pub(crate) instance: [u8; 32],
    pub(crate) project: ProjectId,
    pub(crate) receipt: ObjectDigest,
    pub(crate) root_floor: ObjectDigest,
    pub(crate) controller_floor: ObjectDigest,
}

impl SourceGenesisAckV1 {
    pub(crate) fn encode(&self) -> [u8; ACK_BYTES] {
        let mut bytes = [0; ACK_BYTES];
        bytes[..8].copy_from_slice(b"AOSSGA01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.instance);
        bytes[48..64].copy_from_slice(self.project.as_bytes());
        bytes[64..96].copy_from_slice(self.receipt.as_bytes());
        bytes[96..128].copy_from_slice(self.root_floor.as_bytes());
        bytes[128..160].copy_from_slice(self.controller_floor.as_bytes());
        let digest = checksum(ACK_DOMAIN, &bytes[..160]);
        bytes[160..].copy_from_slice(digest.as_bytes());
        bytes
    }

    pub(crate) fn digest(&self) -> ObjectDigest {
        checksum(
            b"aos.sandbox.source-tree-genesis.ack-record.v1\0",
            &self.encode(),
        )
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        require_frame(bytes, b"AOSSGA01", ACK_BYTES, ACK_DOMAIN)?;
        let value = Self {
            instance: array(bytes, 16)?,
            project: ProjectId::from_bytes(array(bytes, 48)?),
            receipt: ObjectDigest::from_bytes(array(bytes, 64)?),
            root_floor: ObjectDigest::from_bytes(array(bytes, 96)?),
            controller_floor: ObjectDigest::from_bytes(array(bytes, 128)?),
        };
        if [value.receipt, value.root_floor, value.controller_floor]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceGenesisRowsV1 {
    pub(crate) receipts: BTreeMap<ProjectId, SourceTreeGenesisReceiptV1>,
    pub(crate) acks: BTreeMap<ProjectId, SourceGenesisAckV1>,
    pub(crate) pending: Option<SourceGenesisPendingV1>,
}

fn current_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<SourceGenesisRowsV1, JournalError> {
    let mut receipts = BTreeMap::new();
    let mut acks = BTreeMap::new();
    for ((namespace, key), bytes) in state {
        if *namespace != RecordNamespace::DesiredState {
            if key.starts_with(KEY_FAMILY_PREFIX) {
                return Err(JournalError::ProtectedBoundary);
            }
            continue;
        }
        if key.starts_with(KEY_FAMILY_PREFIX)
            && key != PENDING_KEY
            && !key.starts_with(RECEIPT_PREFIX)
            && !key.starts_with(ACK_PREFIX)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if let Some(project) = project_key(key, RECEIPT_PREFIX)? {
            let receipt = SourceTreeGenesisReceiptV1::decode(bytes)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if receipt.project() != project {
                return Err(JournalError::ProtectedBoundary);
            }
            receipts.insert(project, receipt);
        } else if let Some(project) = project_key(key, ACK_PREFIX)? {
            let ack = SourceGenesisAckV1::decode(bytes)?;
            if ack.project != project {
                return Err(JournalError::ProtectedBoundary);
            }
            acks.insert(project, ack);
        }
    }
    let pending = state
        .get(&(RecordNamespace::DesiredState, PENDING_KEY.to_vec()))
        .map(|bytes| SourceGenesisPendingV1::decode(bytes))
        .transpose()?;
    if let Some(pending) = &pending {
        let receipt = receipts
            .get(&pending.project)
            .ok_or(JournalError::ProtectedBoundary)?;
        if receipt.digest() != pending.receipt
            || receipt.instance() != pending.instance
            || receipt.intent_digest() != pending.intent
            || acks.contains_key(&pending.project)
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    for (project, receipt) in &receipts {
        match acks.get(project) {
            Some(ack) if ack.receipt == receipt.digest() && ack.instance == receipt.instance() => {}
            None if pending.as_ref().is_some_and(|row| row.project == *project) => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }
    }
    if acks.keys().any(|project| !receipts.contains_key(project)) {
        return Err(JournalError::ProtectedBoundary);
    }
    if let Some(original) = receipts.values().next()
        && receipts
            .values()
            .any(|receipt| receipt.instance() != original.instance())
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(SourceGenesisRowsV1 {
        receipts,
        acks,
        pending,
    })
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceGenesisTransitionV1,
) -> Result<(), JournalError> {
    let rows = current_rows(state)?;
    match transition {
        SourceGenesisTransitionV1::None => {
            if rows.pending.is_some()
                || transaction
                    .records()
                    .iter()
                    .any(|record| protected_record(record, &rows))
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        SourceGenesisTransitionV1::Append => {
            if rows.pending.is_some() || transaction.records().len() != 4 {
                return Err(JournalError::ProtectedBoundary);
            }
            let records = transaction.records();
            let receipt = SourceTreeGenesisReceiptV1::decode(
                records[2].value().ok_or(JournalError::ProtectedBoundary)?,
            )
            .map_err(|_| JournalError::ProtectedBoundary)?;
            let pending = SourceGenesisPendingV1::decode(
                records[3].value().ok_or(JournalError::ProtectedBoundary)?,
            )?;
            if !receipt.matches_members(
                records[0].value().ok_or(JournalError::ProtectedBoundary)?,
                records[1].value().ok_or(JournalError::ProtectedBoundary)?,
            ) {
                return Err(JournalError::ProtectedBoundary);
            }
            if rows.receipts.contains_key(&receipt.project())
                || rows
                    .receipts
                    .values()
                    .any(|prior| prior.instance() != receipt.instance())
                || pending.project != receipt.project()
                || pending.instance != receipt.instance()
                || pending.intent != receipt.intent_digest()
                || pending.receipt != receipt.digest()
                || records[2].namespace() != RecordNamespace::DesiredState
                || records[2].key() != receipt_key(receipt.project())
                || records[3].namespace() != RecordNamespace::DesiredState
                || records[3].key() != PENDING_KEY
            {
                return Err(JournalError::ProtectedBoundary);
            }
            for (record, kind) in records[..2].iter().zip([
                HierarchyProtectedRecordKindV1::Tree,
                HierarchyProtectedRecordKindV1::TreeLineage,
            ]) {
                let key = HierarchyProtectedJournalKeyV1::decode(record.key())
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                if record.namespace() != RecordNamespace::DesiredState
                    || key.kind() != kind
                    || key.identity().get(..16) != Some(receipt.project().as_bytes().as_slice())
                    || state.contains_key(&(record.namespace(), record.key().to_vec()))
                    || record.value().is_none()
                {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
        }
        SourceGenesisTransitionV1::Anchor => {
            let pending = rows.pending.ok_or(JournalError::ProtectedBoundary)?;
            let [delete, record] = transaction.records() else {
                return Err(JournalError::ProtectedBoundary);
            };
            let ack =
                SourceGenesisAckV1::decode(record.value().ok_or(JournalError::ProtectedBoundary)?)?;
            if delete.namespace() != RecordNamespace::DesiredState
                || delete.key() != PENDING_KEY
                || delete.value().is_some()
                || record.namespace() != RecordNamespace::DesiredState
                || record.key() != ack_key(pending.project)
                || ack.instance != pending.instance
                || ack.project != pending.project
                || ack.receipt != pending.receipt
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    Ok(())
}

fn protected_record(record: &JournalRecord, rows: &SourceGenesisRowsV1) -> bool {
    if record.key().starts_with(KEY_FAMILY_PREFIX) {
        return true;
    }
    if record.namespace() != RecordNamespace::DesiredState {
        return false;
    }
    let Ok(key) = HierarchyProtectedJournalKeyV1::decode(record.key()) else {
        return false;
    };
    if !matches!(
        key.kind(),
        HierarchyProtectedRecordKindV1::Tree | HierarchyProtectedRecordKindV1::TreeLineage
    ) {
        return false;
    }
    key.identity()
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .map(ProjectId::from_bytes)
        .is_some_and(|project| rows.receipts.contains_key(&project))
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if current_rows(state)?.pending.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl Journal {
    pub(crate) fn source_tree_genesis_rows_v1(&self) -> Result<SourceGenesisRowsV1, JournalError> {
        self.ensure_healthy()?;
        current_rows(&self.state)
    }

    pub(crate) fn commit_source_tree_genesis_v1(
        &mut self,
        transaction: &JournalTransaction,
        transition: SourceGenesisTransitionV1,
    ) -> Result<(), JournalError> {
        self.commit_with_capacity_scope_and_source_genesis(
            transaction,
            None,
            false,
            false,
            false,
            false,
            false,
            super::SourceProjectAdmissionTransition::None,
            super::controller_source_genesis::ControllerSourceGenesisTransition::None,
            transition,
            super::RootSourceGenesisTransitionV1::None,
        )?;
        Ok(())
    }

    pub(crate) fn preflight_source_tree_genesis_v1(
        &self,
        transactions: &[JournalTransaction],
        transitions: &[SourceGenesisTransitionV1],
    ) -> Result<(), JournalError> {
        self.preflight_transactions_with_capacity_scope_and_source_genesis(
            transactions,
            None,
            false,
            false,
            None,
            None,
            Some(transitions),
        )
    }
}

pub(crate) fn receipt_key(project: ProjectId) -> Vec<u8> {
    key(RECEIPT_PREFIX, project)
}
pub(crate) fn ack_key(project: ProjectId) -> Vec<u8> {
    key(ACK_PREFIX, project)
}

fn key(prefix: &[u8], project: ProjectId) -> Vec<u8> {
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(project.as_bytes());
    bytes
}

fn project_key(key: &[u8], prefix: &[u8]) -> Result<Option<ProjectId>, JournalError> {
    if !key.starts_with(prefix) {
        return Ok(None);
    }
    let project = ProjectId::from_bytes(array(key, prefix.len())?);
    if key.len() != prefix.len() + 16 || project.as_bytes() == &[0; 16] {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(Some(project))
}

fn require_frame(
    bytes: &[u8],
    magic: &[u8; 8],
    width: usize,
    domain: &[u8],
) -> Result<(), JournalError> {
    if bytes.len() != width
        || &bytes[..8] != magic
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[16..48] == [0; 32]
        || bytes[48..64] == [0; 16]
        || bytes[width - 32..] != *checksum(domain, &bytes[..width - 32]).as_bytes()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn checksum(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], JournalError> {
    bytes
        .get(offset..offset + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
