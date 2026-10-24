//! Owns canonical Source genesis rows and their complete saved-family fold.
//!
//! The fold checks every supplied namespace/key before joining receipt, ACK and
//! pending rows. Its caller-selected error type is only a lossless mechanical
//! error projection; it grants no writer, currentness, floor or payment.
//!
//! ```text
//! pending AOSSGP01[224] = framing | instance | project | intent | receipt |
//! nonce | saved directory/journal/lock identities | checksum
//! ACK AOSSGA01[192] = framing | instance | project | receipt |
//! Root floor | Controller floor | checksum
//! ```

use std::collections::BTreeMap;
use aos_sandbox_model::{ObjectDigest, ProjectId, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use sha2::{Digest as _, Sha256};
use crate::genesis::SourceTreeGenesisReceiptV1;

/// Names the canonical saved genesis key family or fixed extent.
pub const PENDING_KEY: &[u8] = b"\0aos-source-tree-genesis-pending-v1\0";
/// Names the canonical saved genesis key family or fixed extent.
pub const KEY_FAMILY_PREFIX: &[u8] = b"\0aos-source-tree-genesis-";
/// Names the canonical saved genesis key family or fixed extent.
pub const RECEIPT_PREFIX: &[u8] = b"\0aos-source-tree-genesis-receipt-v1\0";
/// Names the canonical saved genesis key family or fixed extent.
pub const ACK_PREFIX: &[u8] = b"\0aos-source-tree-genesis-ack-v1\0";
/// Names the canonical saved genesis key family or fixed extent.
pub const PENDING_BYTES: usize = 224;
/// Names the canonical saved genesis key family or fixed extent.
pub const ACK_BYTES: usize = 192;
const PENDING_DOMAIN: &[u8] = b"aos.sandbox.source-tree-genesis.pending.v1\0";
const ACK_DOMAIN: &[u8] = b"aos.sandbox.source-tree-genesis.ack.v1\0";


/// Describes canonical saved genesis DATA without live writer or grant authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceGenesisPendingV1 {
    /// Retains the exact historical field or row family.
    pub instance: [u8; 32],
    /// Retains the exact historical field or row family.
    pub project: ProjectId,
    /// Retains the exact historical field or row family.
    pub intent: ObjectDigest,
    /// Retains the exact historical field or row family.
    pub receipt: ObjectDigest,
    /// Retains the exact historical field or row family.
    pub nonce: [u8; 16],
    /// Retains the exact historical field or row family.
    pub names: ProtectedJournalNamesV1,
}

impl SourceGenesisPendingV1 {
    /// Encodes the exact canonical saved row.
    pub fn encode(&self) -> [u8; PENDING_BYTES] {
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

    /// Decodes and compares the exact canonical saved row.
    ///
    /// # Errors
    /// Rejects noncanonical framing or inconsistent saved row bindings.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        require_frame(bytes, b"AOSSGP01", PENDING_BYTES, PENDING_DOMAIN)?;
        let value = Self {
            instance: array(bytes, 16)?,
            project: ProjectId::from_bytes(array(bytes, 48)?),
            intent: ObjectDigest::from_bytes(array(bytes, 64)?),
            receipt: ObjectDigest::from_bytes(array(bytes, 96)?),
            nonce: array(bytes, 128)?,
            names: ProtectedJournalNamesV1::from_bytes(&bytes[144..192])
                .map_err(|_| JournalError::ProtectedBoundary)?,
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

/// Describes canonical saved genesis DATA without live writer or grant authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceGenesisAckV1 {
    /// Retains the exact historical field or row family.
    pub instance: [u8; 32],
    /// Retains the exact historical field or row family.
    pub project: ProjectId,
    /// Retains the exact historical field or row family.
    pub receipt: ObjectDigest,
    /// Retains the exact historical field or row family.
    pub root_floor: ObjectDigest,
    /// Retains the exact historical field or row family.
    pub controller_floor: ObjectDigest,
}

impl SourceGenesisAckV1 {
    /// Encodes the exact canonical saved row.
    pub fn encode(&self) -> [u8; ACK_BYTES] {
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

    /// Commits the exact canonical saved row bytes.
    pub fn digest(&self) -> ObjectDigest {
        checksum(
            b"aos.sandbox.source-tree-genesis.ack-record.v1\0",
            &self.encode(),
        )
    }

    /// Decodes and compares the exact canonical saved row.
    ///
    /// # Errors
    /// Rejects noncanonical framing or inconsistent saved row bindings.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
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

// Pending/ACK decoding is a fixed consuming DATA recipe. It installs no
// namespace entries; its conservative stack peak is prepaid by the real
// enclosing rows/mutation admission instead of per-field result reservoirs.
/// Bounds fixed decoder and actual caller-error projection stack memory.
pub fn fixed_row_decode_peak_bytes_v1<E>() -> Option<usize> {
    use std::mem::size_of;

    size_of::<SourceGenesisPendingV1>().checked_mul(4)?
        .checked_add(size_of::<SourceGenesisAckV1>().checked_mul(4)?)?
        .checked_add(size_of::<Result<SourceGenesisPendingV1, E>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<SourceGenesisAckV1, E>>().checked_mul(2)?)?
        .checked_add(size_of::<[u8; PENDING_BYTES]>().checked_mul(2)?)?
        .checked_add(size_of::<[u8; ACK_BYTES]>().checked_mul(2)?)?
        .checked_add(size_of::<ProtectedJournalNamesV1>().checked_mul(4)?)?
        .checked_add(size_of::<Result<SourceGenesisPendingV1, JournalError>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<SourceGenesisAckV1, JournalError>>().checked_mul(2)?)?
        .checked_add(size_of::<Sha256>().checked_mul(2)?)?
        .checked_add(size_of::<[ObjectDigest; 3]>().checked_mul(2)?)?
        .checked_add(size_of::<[usize; 16]>())?
        .checked_add(size_of::<[&'static [u8]; 8]>())
}

/// Describes canonical saved genesis DATA without live writer or grant authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceGenesisRowsV1 {
    /// Retains the exact historical field or row family.
    pub receipts: BTreeMap<ProjectId, SourceTreeGenesisReceiptV1>,
    /// Retains the exact historical field or row family.
    pub acks: BTreeMap<ProjectId, SourceGenesisAckV1>,
    /// Retains the exact historical field or row family.
    pub pending: Option<SourceGenesisPendingV1>,
}

/// Decodes and compares the exact canonical saved row.
///
/// # Errors
/// Rejects noncanonical framing or inconsistent saved row bindings.
pub fn current_rows<E: From<JournalError> + std::error::Error + 'static>(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<SourceGenesisRowsV1, E> {
    current_rows_with_originals::<E, crate::genesis::SourceGenesisReceiptDataErrorV1>(state, None)
}

/// Decodes and compares the exact canonical saved row.
///
/// # Errors
/// Rejects noncanonical framing or inconsistent saved row bindings.
pub fn decode_receipt_with_originals<E, R>(
    bytes: &[u8], destination: Option<&mut Option<crate::genesis::SourceGenesisReceiptDecodeOriginalsV1<R>>>,
) -> Result<SourceTreeGenesisReceiptV1, E>
where
    E: From<JournalError> + std::error::Error + 'static,
    R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static,
{
    match destination {
        Some(destination) => {
            *destination = Some(crate::genesis::SourceGenesisReceiptDecodeOriginalsV1::new());
            let capture = destination.as_mut().ok_or(E::from(JournalError::ProtectedBoundary))?;
            capture.observe_once(bytes).map_err(|_| E::from(JournalError::ProtectedBoundary))?;
            capture.take_receipt_once().ok_or(E::from(JournalError::ProtectedBoundary))
        }
        None => SourceTreeGenesisReceiptV1::decode(bytes).map_err(|_| E::from(JournalError::ProtectedBoundary)),
    }
}

fn current_rows_with_originals<E, R>(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    originals: Option<&mut SourceGenesisRowsOriginalsV1<E, R>>,
) -> Result<SourceGenesisRowsV1, E>
where
    E: From<JournalError> + std::error::Error + 'static,
    R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static,
{
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
    let (receipts_sink, acks_sink, pending_sink, receipt_sink, ack_sink, mut receipt_decode_slot) = match originals {
        Some(originals) => (Some(&mut originals.receipts), Some(&mut originals.acks),
            Some(&mut originals.pending), Some(&mut originals.current_receipt), Some(&mut originals.current_ack),
            Some(&mut originals.receipt_decode)),
        None => (None, None, None, None, None, None),
    };
    let mut receipts = CaptureOnDropV1::new(BTreeMap::new(), receipts_sink);
    let mut acks = CaptureOnDropV1::new(BTreeMap::new(), acks_sink);
    let mut receipt_slot = receipt_sink;
    let mut ack_slot = ack_sink;
    for ((namespace, key), bytes) in state {
        if *namespace != RecordNamespace::DesiredState {
            if key.starts_with(KEY_FAMILY_PREFIX) {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            continue;
        }
        if key.starts_with(KEY_FAMILY_PREFIX)
            && key != PENDING_KEY
            && !key.starts_with(RECEIPT_PREFIX)
            && !key.starts_with(ACK_PREFIX)
        {
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        if let Some(project) = project_key(key, RECEIPT_PREFIX)? {
            let receipt = decode_receipt_with_originals::<E, R>(bytes, receipt_decode_slot.as_deref_mut())?;
            let receipt = CaptureOnDropV1::new(receipt, receipt_slot.as_deref_mut());
            if receipt.project() != project {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            receipts.insert(project, receipt.into_inner());
            // Complete primitive validation and exact row identity are this
            // decoder's last borrowers. The actual receipt now lives in the map.
            if let Some(destination) = receipt_decode_slot.as_deref_mut() { drop(destination.take()); }
        } else if let Some(project) = project_key(key, ACK_PREFIX)? {
            let ack = CaptureOnDropV1::new(SourceGenesisAckV1::decode(bytes)?, ack_slot.as_deref_mut());
            if ack.project != project {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            acks.insert(project, ack.into_inner());
        }
    }
    let pending = CaptureOnDropV1::new(state
        .get(&(RecordNamespace::DesiredState, PENDING_KEY.to_vec()))
        .map(|bytes| SourceGenesisPendingV1::decode(bytes))
        .transpose()?, pending_sink);
    if let Some(pending) = &*pending {
        let receipt = receipts
            .get(&pending.project)
            .ok_or(E::from(JournalError::ProtectedBoundary))?;
        if receipt.digest() != pending.receipt
            || receipt.instance() != pending.instance
            || receipt.intent_digest() != pending.intent
            || acks.contains_key(&pending.project)
        {
            return Err(E::from(JournalError::ProtectedBoundary));
        }
    }
    for (project, receipt) in receipts.iter() {
        match acks.get(project) {
            Some(ack) if ack.receipt == receipt.digest() && ack.instance == receipt.instance() => {}
            None if pending.as_ref().is_some_and(|row| row.project == *project) => {}
            _ => return Err(E::from(JournalError::ProtectedBoundary)),
        }
    }
    if acks.keys().any(|project| !receipts.contains_key(project)) {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    if let Some(original) = receipts.values().next()
        && receipts
            .values()
            .any(|receipt| receipt.instance() != original.instance())
    {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    Ok(SourceGenesisRowsV1 {
        receipts: receipts.into_inner(),
        acks: acks.into_inner(),
        pending: pending.into_inner(),
    })
}

/// Holds reached pure row work and the actual caller-projected error.
pub struct SourceGenesisRowsOriginalsV1<E, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    /// Retains the actual `receipts` comparison destination.
    pub receipts: Option<BTreeMap<ProjectId, SourceTreeGenesisReceiptV1>>,
    /// Retains the actual `acks` comparison destination.
    pub acks: Option<BTreeMap<ProjectId, SourceGenesisAckV1>>,
    /// Retains the actual `pending` comparison destination.
    pub pending: Option<Option<SourceGenesisPendingV1>>,
    /// Retains the actual `current_receipt` comparison destination.
    pub current_receipt: Option<SourceTreeGenesisReceiptV1>,
    /// Retains the actual `current_ack` comparison destination.
    pub current_ack: Option<SourceGenesisAckV1>,
    /// Retains the actual `receipt_decode` comparison destination.
    pub receipt_decode: Option<crate::genesis::SourceGenesisReceiptDecodeOriginalsV1<R>>,
    /// Retains the actual `rows` comparison destination.
    #[doc(hidden)]
    pub rows: Option<SourceGenesisRowsV1>,
    /// Retains the actual `result` comparison destination.
    #[doc(hidden)]
    pub result: Option<Result<(), E>>,
    /// Retains the actual `closed` comparison destination.
    #[doc(hidden)]
    pub closed: Option<E>,
    /// Retains the actual `entered` comparison destination.
    #[doc(hidden)]
    pub entered: bool,
}

impl<E, R> SourceGenesisRowsOriginalsV1<E, R>
where
    E: From<JournalError> + std::error::Error + 'static,
    R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static,
{
    /// Creates an empty comparison destination without IO or admission.
    pub const fn new() -> Self {
        Self {
            receipts: None,
            acks: None,
            pending: None,
            current_receipt: None,
            current_ack: None,
            receipt_decode: None,
            rows: None,
            result: None,
            closed: None,
            entered: false,
        }
    }

    /// Runs the sole saved-family fold once and retains its actual returned error.
    ///
    /// # Errors
    /// Rejects a repeated attempt, malformed row or inconsistent family join.
    pub fn observe_once(
        &mut self,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.result = Some(match current_rows_with_originals::<E, R>(state, Some(self)) {
            Ok(rows) => {
                self.rows = Some(rows);
                Ok(())
            }
            Err(cause) => Err(cause),
        });
        match &self.result {
            Some(Ok(())) => Ok(()),
            _ => Err(E::from(JournalError::ProtectedBoundary)),
        }
    }

    /// Borrows complete rows only while the comparison remains successful.
    pub fn rows(&self) -> Option<&SourceGenesisRowsV1> {
        if self.failure().is_some() {
            None
        } else {
            self.rows.as_ref()
        }
    }

    /// Moves complete comparison rows once without issuing a live grant.
    ///
    /// # Errors
    /// Rejects failed, repeated or incomplete output transfer.
    pub fn take_rows_once(&mut self) -> Result<SourceGenesisRowsV1, E> {
        if self.failure().is_some() {
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        match self.rows.take() {
            Some(rows) => Ok(rows),
            None => {
                self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
                Err(E::from(JournalError::ProtectedBoundary))
            }
        }
    }

    /// Borrows the original whole fold error before any closed-owner refusal.
    pub fn failure(&self) -> Option<&E> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .or(self.closed.as_ref())
    }

    /// Borrows the reached receipt codec cause or original fold error.
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receipt_decode.as_ref().and_then(|capture| capture.failure())
            .or_else(|| self.failure().map(|cause| cause as _))
    }

    /// Returns the existing fixed representation demand without new namespace entries.
    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
        type ReceiptCapture<R> = crate::genesis::SourceGenesisReceiptDecodeOriginalsV1<R>;
        let (receipt_bytes, _) = ReceiptCapture::<R>::fixed_footprint_v1()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(fixed_row_decode_peak_bytes_v1::<E>()?)?
            .checked_add(receipt_bytes.checked_sub(std::mem::size_of::<ReceiptCapture<R>>().checked_mul(2)?)?)?
            .checked_add(std::mem::size_of::<Option<&mut Option<ReceiptCapture<R>>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, BTreeMap<ProjectId, SourceTreeGenesisReceiptV1>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, BTreeMap<ProjectId, SourceGenesisAckV1>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, Option<SourceGenesisPendingV1>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, SourceTreeGenesisReceiptV1>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, SourceGenesisAckV1>>())?
            .checked_add(PENDING_KEY.len())?
            .checked_add(std::mem::size_of::<(RecordNamespace, Vec<u8>)>())?;
        // Fixed parser controls and buffers create no namespace entries.
        // Actual receipt/ACK map cardinality is charged by the enclosing
        // reached-row supplier before this fold runs.
        Some((bytes, 0))
    }
}

/// Encodes the canonical saved receipt key for a project.
pub fn receipt_key(project: ProjectId) -> Vec<u8> {
    key(RECEIPT_PREFIX, project)
}
/// Encodes the canonical saved acknowledgment key for a project.
pub fn ack_key(project: ProjectId) -> Vec<u8> {
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

/// Selects a saved Source genesis comparison without native crossing authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SourceGenesisTransitionV1 {
    None,
    Append,
    Anchor,
    FirstSuccessorAppend,
    FirstSuccessorAck,
}


/// Owns the canonical protected-key classifier and its original false-on-decode-error rule.
pub mod classification;


use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
pub fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if current_rows::<JournalError>(state)?.pending.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub fn recognize_replayed_transition(
    transaction: &JournalTransaction,
) -> Result<SourceGenesisTransitionV1, JournalError> {
    let touches = transaction.records().iter().any(|record| record.key().starts_with(KEY_FAMILY_PREFIX));
    if !touches {
        return Ok(SourceGenesisTransitionV1::None);
    }
    if transaction.records().len() == 4 {
        return Ok(SourceGenesisTransitionV1::Append);
    }
    if transaction.records().len() == 2 {
        return Ok(SourceGenesisTransitionV1::Anchor);
    }
    Err(JournalError::ProtectedBoundary)
}


pub mod mutation;
pub use mutation::SourceGenesisMutationOriginalsV1;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;
use super::hierarchy_records::{HierarchyProtectedJournalKeyV1, HierarchyProtectedRecordKindV1};

/// Validates the original saved Source genesis mutation shape.
///
/// # Errors
/// Rejects an unjoined predecessor, changed family or forbidden mutation.
pub fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceGenesisTransitionV1,
) -> Result<(), JournalError> {
    require_no_mutation_with_originals::<JournalError, DomainLedgerDataError, crate::genesis::SourceGenesisReceiptDataErrorV1>(state, transaction, transition, None)
}

/// Validates the original saved Source genesis mutation shape.
///
/// # Errors
/// Rejects an unjoined predecessor, changed family or forbidden mutation.
/// Validates the original saved Source genesis mutation shape.
///
/// # Errors
/// Rejects an unjoined predecessor, changed family or forbidden mutation.
pub fn require_no_mutation_with_originals<
    E: From<JournalError> + std::error::Error + 'static,
    H: From<DomainLedgerDataError> + std::error::Error + 'static,
    R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static,
>(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceGenesisTransitionV1,
    originals: Option<&mut SourceGenesisMutationOriginalsV1<E, H, R>>,
) -> Result<(), E> {
    match originals {
        Some(originals) => originals.observe_once(state, transaction, transition),
        None => require_no_mutation_engine::<E, H, R>(state, transaction, transition, None),
    }
}

/// Validates the original saved Source genesis mutation shape.
///
/// # Errors
/// Rejects an unjoined predecessor, changed family or forbidden mutation.
/// Validates the original saved Source genesis mutation shape.
///
/// # Errors
/// Rejects an unjoined predecessor, changed family or forbidden mutation.
pub fn require_no_mutation_engine<
    E: From<JournalError> + std::error::Error + 'static,
    H: From<DomainLedgerDataError> + std::error::Error + 'static,
    R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static,
>(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceGenesisTransitionV1,
    originals: Option<&mut SourceGenesisMutationOriginalsV1<E, H, R>>,
) -> Result<(), E> {
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
    use aos_sandbox_protocol::domain_ledger::records::decode_domain_key_retaining_v1;
    let (parser, rows_sink, receipt_sink, pending_sink, ack_sink, mut key_sink, predecessor, classification, receipt_decoder) = match originals {
        Some(originals) => (
            Some(&mut originals.parser), Some(&mut originals.rows), Some(&mut originals.receipt),
            Some(&mut originals.pending), Some(&mut originals.ack), Some(&mut originals.key),
            Some(&mut originals.predecessor), Some(&mut originals.classification),
            Some(&mut originals.receipt_decode),
        ),
        None => (None, None, None, None, None, None, None, None, None),
    };
    let rows = match parser {
        Some(originals) => { originals.observe_once(state)?; originals.take_rows_once()? }
        None => current_rows::<E>(state)?,
    };
    let mut rows = CaptureOnDropV1::new(rows, rows_sink);
    match transition {
        SourceGenesisTransitionV1::FirstSuccessorAppend
        | SourceGenesisTransitionV1::FirstSuccessorAck => {
            match predecessor {
                Some(originals) => super::source_tree_successor::require_genesis_predecessor_with_originals(
                    state, transaction, Some(originals),
                )?,
                None => super::source_tree_successor::require_genesis_predecessor(state, transaction)?,
            }
            if rows.pending.is_some()
                || transaction.records().iter().any(|record| record.key().starts_with(KEY_FAMILY_PREFIX))
            {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
        }
        SourceGenesisTransitionV1::None => {
            match classification {
                Some(originals) => {
                    // A pending row short-circuits before any key decode in
                    // both modes. Ignored key errors remain false DATA.
                    if rows.pending.is_some()
                        || originals.observe_once(transaction.records(), &rows)?
                    {
                        return Err(E::from(JournalError::ProtectedBoundary));
                    }
                }
                None => {
                    if rows.pending.is_some()
                        || transaction
                            .records()
                            .iter()
                            .any(|record| classification::protected_record(record, &rows))
                    {
                        return Err(E::from(JournalError::ProtectedBoundary));
                    }
                }
            }
        }
        SourceGenesisTransitionV1::Append => {
            if rows.pending.is_some() || transaction.records().len() != 4 {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            let records = transaction.records();
            let receipt = decode_receipt_with_originals::<E, R>(
                records[2].value().ok_or(E::from(JournalError::ProtectedBoundary))?, receipt_decoder,
            )?;
            let receipt = CaptureOnDropV1::new(receipt, receipt_sink);
            let pending = SourceGenesisPendingV1::decode(
                records[3].value().ok_or(E::from(JournalError::ProtectedBoundary))?,
            )?;
            let pending = CaptureOnDropV1::new(pending, pending_sink);
            if !receipt.matches_members(
                records[0].value().ok_or(E::from(JournalError::ProtectedBoundary))?,
                records[1].value().ok_or(E::from(JournalError::ProtectedBoundary))?,
            ) {
                return Err(E::from(JournalError::ProtectedBoundary));
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
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            for (record, kind) in records[..2].iter().zip([
                HierarchyProtectedRecordKindV1::Tree,
                HierarchyProtectedRecordKindV1::TreeLineage,
            ]) {
                let ordinary_key;
                let key = match key_sink.as_deref_mut() {
                    Some(slot) => {
                        *slot = Some(aos_sandbox_protocol::domain_ledger::records::DomainKeyDecodeCaptureV1::new());
                        let originals = slot.as_mut().ok_or(E::from(JournalError::ProtectedBoundary))?;
                        decode_domain_key_retaining_v1(record.key(), originals)
                            .map_err(|_| E::from(JournalError::ProtectedBoundary))?;
                        originals.key().ok_or(E::from(JournalError::ProtectedBoundary))?
                    }
                    None => {
                        ordinary_key = HierarchyProtectedJournalKeyV1::decode(record.key())
                            .map_err(|_| E::from(JournalError::ProtectedBoundary))?;
                        &ordinary_key
                    }
                };
                if record.namespace() != RecordNamespace::DesiredState
                    || key.kind() != kind
                    || key.identity().get(..16) != Some(receipt.project().as_bytes().as_slice())
                    || state.contains_key(&(record.namespace(), record.key().to_vec()))
                    || record.value().is_none()
                {
                    return Err(E::from(JournalError::ProtectedBoundary));
                }
                if let Some(slot) = key_sink.as_deref_mut() {
                    // This exact key's final namespace/kind/identity/name test
                    // completed; dispose its pure positive leaf before the next.
                    drop(slot.take());
                }
            }
        }
        SourceGenesisTransitionV1::Anchor => {
            // Taking the field keeps the ordinary remaining-map cleanup order;
            // selected mode retains the moved pending beside those same maps.
            let pending = rows.pending.take().ok_or(E::from(JournalError::ProtectedBoundary))?;
            let pending = CaptureOnDropV1::new(pending, pending_sink);
            let [delete, record] = transaction.records() else {
                return Err(E::from(JournalError::ProtectedBoundary));
            };
            let ack =
                SourceGenesisAckV1::decode(record.value().ok_or(E::from(JournalError::ProtectedBoundary))?)?;
            let ack = CaptureOnDropV1::new(ack, ack_sink);
            if delete.namespace() != RecordNamespace::DesiredState
                || delete.key() != PENDING_KEY
                || delete.value().is_some()
                || record.namespace() != RecordNamespace::DesiredState
                || record.key() != ack_key(pending.project)
                || ack.instance != pending.instance
                || ack.project != pending.project
                || ack.receipt != pending.receipt
            {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
        }
    }
    Ok(())
}
