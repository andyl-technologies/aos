//! Borrows the original Controller journal for exact Repair orchestration.
//!
//! Fixed role owners never escape this facade. Query IDs are reserved before
//! send, exact physical requests remain in immutable admission custody, and a
//! sent Execute may subsequently use only read-only owning-journal recovery.
//!
//! ```text
//! storage-repair-progress-v1/<operation[16]>/<phase:u8>:
//! AOSORP01 | operation[16] | phase:u8 | zero[7] | payload-length:u32be | payload
//! ```

use aos_sandbox_core::OperationId;
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::operator_storage_repair_transport_v3::{
    OperatorStorageRepairModeV3, OperatorStorageRepairRequestV3, OperatorStorageRepairResultV3,
};
use aos_sandbox_protocol::{ProtocolId, decode_request_envelope};
use sha2::{Digest as _, Sha256};

use super::before::RepairBeforeV1 as _;
use super::probe_challenge::RepairProbeChallengeV1 as _;
use super::terminal::RepairTerminalProofV1 as _;
use super::transport::RepairTransportV1 as _;
use super::{
    OperatorRecoveryIssuanceErrorV1, ProtectedOperatorRecoverySignerV1, RepairJournalOwnerV1,
    hash, protected_query_roles,
};
use crate::resource_inventory::ResourceInventoryServiceIdentity;
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const PROGRESS_PREFIX: &[u8] = b"storage-repair-progress-v1/";
const PROGRESS_MAGIC: &[u8; 8] = b"AOSORP01";
const PROGRESS_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-progress.v1\0";
const PREPARE_SENT: u8 = 1;
const PROBE_RETAINED: u8 = 2;
const EXECUTE_SENT: u8 = 3;
const OWNER_PAIR: u8 = 4;
const BEFORE_PACKET: u8 = 5;
const AFTER_PACKET: u8 = 6;
const TERMINAL_PACKET: u8 = 7;
const HOLD_REQUEST: u8 = 8;
const SETTLEMENT_READBACK: u8 = 9;
const MAXIMUM_TERMINAL_EPOCHS: u8 = 4;
const TERMINAL_EPOCH_STRIDE: u8 = 3;

mod terminal_continuation;

/// Reports exact terminal settlement without a generic Apply receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorStorageRepairTerminalV1 {
    /// The exact six-row successor was committed and Storage acknowledged it.
    Committed,
    /// The exact committed successor and owner settlement were recovered.
    Replay,
    /// An exact definite no-commit was acknowledged without another physical Apply.
    NotCommitted,
    /// Physical Repair completed, but its original public predecessor was replaced.
    OriginalPreconditionReplaced,
}

/// Exposes retained Repair data for independently authenticated history recovery.
///
/// Packet bytes and state flags are historical data, never live heldness or
/// authentication constructors. A session owner must reverify an original
/// packet before supplying a typed outcome back to this facade.
pub struct StorageRepairProgressV1 {
    /// Original authenticated admission Inventory identity; historical DATA only.
    pub admission_request_id: [u8; 16],
    /// Exact admission Inventory packet co-committed with the original attempt.
    pub admission_packet: Vec<u8>,
    /// Original challenged pre-effect request, including a possibly lost response.
    pub before_request_id: Option<[u8; 16]>,
    /// Exact canonical pre-effect outcome, if durably retained.
    pub before_packet: Option<Vec<u8>>,
    /// Original challenged post-effect request, including a possibly lost response.
    pub after_request_id: Option<[u8; 16]>,
    /// Exact canonical post-effect outcome, if durably retained.
    pub after_packet: Option<Vec<u8>>,
    /// Original challenged post-proof request, including a possibly lost response.
    pub terminal_request_id: Option<[u8; 16]>,
    /// Exact canonical post-proof outcome; no new ordinary query is allowed while held.
    pub terminal_packet: Option<Vec<u8>>,
    /// Exact authenticated Prepare attestation, if retained.
    pub prepared_probe: Option<Vec<u8>>,
    /// Exact owner-signed physical evidence and receipt, if retained.
    pub owner_pair: Option<([u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2], [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2])>,
    /// Indicates that the existing checked before/after proof row is present.
    pub proof_sealed: bool,
    /// Indicates that original signed hold custody was durably reserved before send.
    pub terminal_hold_sent: bool,
    /// Indicates that a terminal row exists; its full cold linkage still needs verification.
    pub terminal_committed: bool,
}

struct BorrowedRepairJournalV1<'journal>(&'journal mut Journal);

impl RepairJournalOwnerV1 for BorrowedRepairJournalV1<'_> {
    fn repair_journal(&mut self) -> &mut Journal {
        self.0
    }
}

/// Retains fixed Repair roles alongside the actual exclusive Controller writer.
///
/// This is a method-specific owner, not a signer, receipt factory, or substitute
/// for a live Storage terminal hold. Its lifetime excludes competing local
/// journal writes while its exact physical/query/terminal crossings run.
pub struct OperatorStorageRepairBridgeV1<'journal> {
    journal: BorrowedRepairJournalV1<'journal>,
    signer: ProtectedOperatorRecoverySignerV1,
    owner: super::receipt::ProtectedStorageRepairReceiptVerifierV2,
}

impl<'journal> OperatorStorageRepairBridgeV1<'journal> {
    /// Reads exact original data without manufacturing authenticated outcomes.
    ///
    /// # Errors
    ///
    /// Rejects malformed, substituted or independently untrusted retained rows.
    pub fn progress_snapshot(&mut self, operation: OperationId) -> Result<StorageRepairProgressV1, OperatorRecoveryIssuanceErrorV1> {
        let (_, envelope) = self.original_request(operation)?;
        let admission_key = [super::admission::INVENTORY_PREFIX, operation.as_bytes()].concat();
        let admission = self.journal.0.get(RecordNamespace::OperatorRecovery, &admission_key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let admission_request_id: [u8; 16] = admission.get(..16).and_then(|bytes| bytes.try_into().ok())
            .filter(|id| *id != [0; 16]).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let admission_packet = admission.get(16..).filter(|bytes| !bytes.is_empty())
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?.to_vec();
        let (issued, intent) = super::terminal::issued_intent(self.journal.0, &self.signer, operation)?;
        let prepared_probe = self.progress(operation, PROBE_RETAINED)?;
        if let Some(packet) = self.progress(operation, PREPARE_SENT)? {
            validate_selected_physical_request(
                &packet, OperatorStorageRepairModeV3::Prepare, &issued.signed_intent,
                &envelope, [0; 32],
            )?;
        }
        if let Some(packet) = self.progress(operation, EXECUTE_SENT)? {
            let probe = prepared_probe.as_deref().ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
            validate_selected_physical_request(
                &packet, OperatorStorageRepairModeV3::Execute, &issued.signed_intent,
                &envelope, Sha256::digest(probe).into(),
            )?;
        }
        let epoch = self.terminal_epoch(operation)?;
        let pair = self.progress(operation, OWNER_PAIR)?;
        let pair_digest = pair.as_ref().map_or([0; 32], |pair| hash(b"aos.sandbox.operator-storage-repair-signed-pair.v2\0", &[pair]));
        let owner_pair = match pair {
            Some(pair) => {
                let evidence = pair.get(..OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2).and_then(|bytes| bytes.try_into().ok()).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
                let receipt = pair.get(OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2..).and_then(|bytes| bytes.try_into().ok()).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
                self.owner.verify_wire_receipt(&intent, &evidence, &receipt)?;
                Some((evidence, receipt))
            }
            None => None,
        };
        let mut challenge = |stage, digest| {
            if self.journal.0.get(RecordNamespace::OperatorRecovery,
                &super::probe_challenge::key(stage, *operation.as_bytes())).is_none()
            {
                return Ok(None);
            }
            super::probe_challenge::read(self.journal.0, &issued, intent.effect_id, stage, digest)
                .map(|challenge| Some(challenge.request_id()))
        };
        let before_request_id = challenge(super::probe_challenge::ProbeStageV1::Before, [0; 32])?;
        let after_request_id = challenge(super::probe_challenge::ProbeStageV1::After, pair_digest)?;
        let mut terminal_request_id = challenge(super::probe_challenge::ProbeStageV1::Terminal, pair_digest)?;
        if epoch > 0 {
            let previous = self.progress(operation, terminal_phase(HOLD_REQUEST, epoch - 1))?
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
            let previous = aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalRequestV4::verify(
                previous.get(16..).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?, self.signer.verifier(), self.signer.generation(),
            ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
            if terminal_request_id == Some(super::take_array(previous.signed_header(), 444)?) {
                terminal_request_id = None;
            }
        }
        let proof_sealed = self.journal.0.get(RecordNamespace::OperatorRecovery,
            &[b"storage-repair-proof-v2/".as_slice(), operation.as_bytes()].concat()).is_some();
        if proof_sealed {
            super::terminal::read_sealed_proof_v2(self.journal.0, &issued, intent.effect_id, pair_digest)?;
        }
        Ok(StorageRepairProgressV1 {
            admission_request_id,
            admission_packet,
            before_request_id, before_packet: self.progress(operation, BEFORE_PACKET)?,
            after_request_id, after_packet: self.progress(operation, AFTER_PACKET)?,
            terminal_request_id, terminal_packet: self.progress(operation, terminal_phase(TERMINAL_PACKET, epoch))?,
            prepared_probe, owner_pair,
            proof_sealed, terminal_hold_sent: self.progress(operation, terminal_phase(HOLD_REQUEST, epoch))?.is_some(),
            terminal_committed: self.journal.0.get(RecordNamespace::OperatorRecovery,
                &[b"storage-repair-terminal-v1/".as_slice(), operation.as_bytes()].concat()).is_some(),
        })
    }
    /// Acquires independently configured roles under the original journal borrow.
    ///
    /// # Errors
    ///
    /// Rejects unprotected or unavailable journal authority and unsafe, absent,
    /// rotated or same-purpose aliased role credentials.
    pub fn claim(journal: &'journal mut Journal) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        journal.ensure_protected_authority().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let (signer, owner) = protected_query_roles()?;
        Ok(Self { journal: BorrowedRepairJournalV1(journal), signer, owner })
    }

    /// Reserves the actual session's pre-effect Query identifier before send.
    ///
    /// # Errors
    ///
    /// Rejects changed issuance/head, existing pre-effect custody, or ambiguity.
    pub fn reserve_before_query(&mut self, operation: OperationId, request: [u8; 16]) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        self.journal.reserve_storage_repair_before_query_v1(&self.signer, operation, request)?;
        Ok(())
    }

    /// Reserves the actual post-effect Query identifier under the exact owner pair.
    ///
    /// # Errors
    ///
    /// Rejects missing before custody, an invalid pair, a sealed proof or ambiguity.
    pub fn reserve_after_query(
        &mut self,
        operation: OperationId,
        evidence: &[u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
        receipt: &[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
        request: [u8; 16],
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        self.journal.reserve_storage_repair_after_query_v1(
            &self.signer, &self.owner, operation, evidence, receipt, request,
        )?;
        Ok(())
    }

    /// Reserves a fresh post-proof Terminal Query before any Storage hold.
    ///
    /// # Errors
    ///
    /// Rejects absent completed proof, invalid original admission, changed roles or ambiguity.
    pub fn reserve_terminal_query(&mut self, operation: OperationId, request: [u8; 16]) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        let epoch = self.terminal_epoch(operation)?;
        if self.progress(operation, terminal_phase(HOLD_REQUEST, epoch))?.is_some()
            || self.progress(operation, terminal_phase(TERMINAL_PACKET, epoch))?.is_some()
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        self.journal.reserve_storage_repair_terminal_query_v1(&self.signer, &self.owner, operation, request)?;
        Ok(())
    }

    /// Retains the exact authenticated before outcome and observes a reserved probe.
    ///
    /// A prior sent Prepare is recovered without authorizing another physical
    /// attempt. The admission envelope is never regenerated or renewed.
    ///
    /// # Errors
    ///
    /// Rejects invalid before evidence or returns outcome-unknown after uncertain
    /// journal/network custody. Recovery never sends Execute.
    pub fn prepare(
        &mut self,
        operation: OperationId,
        before: &AuthenticatedBrokerMethodOutcomeV1,
        storage: &ResourceInventoryServiceIdentity,
    ) -> Result<Vec<u8>, OperatorRecoveryIssuanceErrorV1> {
        let (body, envelope) = self.original_request(operation)?;
        self.journal.reserve_storage_repair_before_v1(&self.signer, operation, &body, before)?;
        self.retain_progress(operation, BEFORE_PACKET, before.canonical_packet())?;
        let sent = self.progress(operation, PREPARE_SENT)?;
        let already_sent = sent.is_some();
        if let Some(packet) = sent {
            let (issued, _) = super::terminal::issued_intent(self.journal.0, &self.signer, operation)?;
            validate_selected_physical_request(
                &packet, OperatorStorageRepairModeV3::Prepare, &issued.signed_intent,
                &envelope, [0; 32],
            )?;
        }
        let selected = if already_sent {
            None
        } else {
            let request = self.select_physical_request(operation, OperatorStorageRepairModeV3::Prepare, &envelope, [0; 32])?;
            self.retain_progress(operation, PREPARE_SENT, &request.encode())?;
            Some(request)
        };
        let mode = if already_sent { OperatorStorageRepairModeV3::RecoverProbe } else { OperatorStorageRepairModeV3::Prepare };
        let authorization = if already_sent { &[][..] } else { envelope.as_slice() };
        let result = self.journal.exchange_storage_repair_v3(
            &self.signer, &self.owner, operation, &body, mode, authorization, None, storage,
            selected.as_ref(),
        ).map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?;
        let OperatorStorageRepairResultV3::Prepared(probe) = result else {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        };
        self.retain_progress(operation, PROBE_RETAINED, &probe)?;
        Ok(probe)
    }

    /// Sends the one exact Execute, or read-only recovery after its sent marker.
    ///
    /// # Errors
    ///
    /// Rejects absent/substituted probe or original custody, and retains
    /// outcome-unknown on any possibly sent effect without owner settlement.
    pub fn execute_or_recover(
        &mut self,
        operation: OperationId,
        storage: &ResourceInventoryServiceIdentity,
    ) -> Result<OperatorStorageRepairResultV3, OperatorRecoveryIssuanceErrorV1> {
        let (body, envelope) = self.original_request(operation)?;
        let probe = self.progress(operation, PROBE_RETAINED)?.ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let sent = self.progress(operation, EXECUTE_SENT)?;
        let already_sent = sent.is_some();
        if let Some(packet) = sent {
            let (issued, _) = super::terminal::issued_intent(self.journal.0, &self.signer, operation)?;
            validate_selected_physical_request(
                &packet, OperatorStorageRepairModeV3::Execute, &issued.signed_intent,
                &envelope, Sha256::digest(&probe).into(),
            )?;
        }
        let selected = if already_sent {
            None
        } else {
            let request = self.select_physical_request(
                operation, OperatorStorageRepairModeV3::Execute, &envelope, Sha256::digest(&probe).into(),
            )?;
            self.retain_progress(operation, EXECUTE_SENT, &request.encode())?;
            Some(request)
        };
        let (mode, authorization, accepted) = if already_sent {
            (OperatorStorageRepairModeV3::RecoverReceipt, &[][..], None)
        } else {
            (OperatorStorageRepairModeV3::Execute, envelope.as_slice(), Some(probe.as_slice()))
        };
        let result = self.journal.exchange_storage_repair_v3(
            &self.signer, &self.owner, operation, &body, mode, authorization, accepted, storage,
            selected.as_ref(),
        ).map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?;
        if let OperatorStorageRepairResultV3::Complete(evidence, receipt) = &result {
            let mut pair = Vec::with_capacity(evidence.len() + receipt.len());
            pair.extend_from_slice(evidence);
            pair.extend_from_slice(receipt);
            self.retain_progress(operation, OWNER_PAIR, &pair)?;
        }
        Ok(result)
    }

    /// Seals existing physical proof from authenticated before/after custody.
    ///
    /// # Errors
    ///
    /// Rejects absent probe/pair, changed challenge/head, mismatched physical
    /// state or uncertain proof commit. No public ledger row advances here.
    pub fn seal_proof(
        &mut self,
        operation: OperationId,
        before: &AuthenticatedBrokerMethodOutcomeV1,
        after: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<[u8; 32], OperatorRecoveryIssuanceErrorV1> {
        let (body, _) = self.original_request(operation)?;
        let probe = self.progress(operation, PROBE_RETAINED)?.ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let pair = self.progress(operation, OWNER_PAIR)?.ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let evidence = pair.get(..OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2)
            .and_then(|value| value.try_into().ok()).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let receipt = pair.get(OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2..)
            .and_then(|value| value.try_into().ok()).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        self.retain_progress(operation, AFTER_PACKET, after.canonical_packet())?;
        self.journal.seal_storage_repair_terminal_proof_v2(
            &self.signer, &self.owner, operation, &body, before, after, &probe, evidence, receipt,
        )
    }

    fn select_physical_request(
        &mut self,
        operation: OperationId,
        mode: OperatorStorageRepairModeV3,
        envelope: &[u8],
        attestation: [u8; 32],
    ) -> Result<OperatorStorageRepairRequestV3, OperatorRecoveryIssuanceErrorV1> {
        let (issued, _) = super::terminal::issued_intent(self.journal.0, &self.signer, operation)?;
        let (request, deadline) = super::transport::coordinates()?;
        OperatorStorageRepairRequestV3::new(
            request, deadline, mode, issued.signed_intent, attestation, envelope.to_vec(),
        ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
    }

    fn original_request(&mut self, operation: OperationId) -> Result<(Vec<u8>, Vec<u8>), OperatorRecoveryIssuanceErrorV1> {
        read_original_request(self.journal.0, operation)
    }

    fn progress(&self, operation: OperationId, phase: u8) -> Result<Option<Vec<u8>>, OperatorRecoveryIssuanceErrorV1> {
        read_progress(self.journal.0, operation, phase).map(|bytes| bytes.map(<[u8]>::to_vec))
    }

    fn retain_progress(&mut self, operation: OperationId, phase: u8, payload: &[u8]) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        if let Some(existing) = self.progress(operation, phase)? {
            return if existing == payload { Ok(()) } else { Err(OperatorRecoveryIssuanceErrorV1::Binding) };
        }
        let mut bytes = Vec::with_capacity(36 + payload.len());
        bytes.extend_from_slice(PROGRESS_MAGIC);
        bytes.extend_from_slice(operation.as_bytes());
        bytes.push(phase);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&u32::try_from(payload.len()).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?.to_be_bytes());
        bytes.extend_from_slice(payload);
        let digest = hash(PROGRESS_DOMAIN, &[&bytes]);
        let transaction = JournalTransaction::new(super::take_array(&digest, 0)?, vec![JournalRecord::put(
            RecordNamespace::OperatorRecovery, progress_key(operation, phase), bytes.clone(),
        )]).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let journal = &mut *self.journal.0;
        let committed = journal.commit(&transaction).is_ok();
        if !committed || journal.get(RecordNamespace::OperatorRecovery, &progress_key(operation, phase)) != Some(bytes.as_slice()) {
            return Err(OperatorRecoveryIssuanceErrorV1::OutcomeUnknown);
        }
        journal.ensure_protected_authority().map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)
    }
}

/// Decodes immutable original transport DATA without minting request authority.
pub(super) fn read_original_request(
    journal: &Journal,
    operation: OperationId,
) -> Result<(Vec<u8>, Vec<u8>), OperatorRecoveryIssuanceErrorV1> {
    let key = [super::admission::ATTEMPT_PREFIX, operation.as_bytes()].concat();
    let bytes = journal.get(RecordNamespace::OperatorRecovery, &key)
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if bytes.len() < 132 || &bytes[..8] != b"AOSORA01"
        || bytes[8..16] != [1, 0, 0, 0, 0, 0, 0, 0]
        || &bytes[16..32] != operation.as_bytes()
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let length = u32::from_be_bytes(super::take_array(bytes, 128)?) as usize;
    if bytes.len() != 132_usize.checked_add(length).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)? {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let envelope = bytes[132..].to_vec();
    let decoded = decode_request_envelope(&envelope, ProtocolId::StorageBroker, 0)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if hash(super::REQUEST_DOMAIN, &[decoded.body()]).as_slice() != &bytes[64..96] {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok((decoded.body().to_vec(), envelope))
}

fn progress_key(operation: OperationId, phase: u8) -> Vec<u8> {
    [PROGRESS_PREFIX, operation.as_bytes(), &[phase]].concat()
}

fn validate_selected_physical_request(
    packet: &[u8],
    mode: OperatorStorageRepairModeV3,
    intent: &[u8; aos_sandbox_core::operator_recovery_effect::OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
    envelope: &[u8],
    attestation: [u8; 32],
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    let request = OperatorStorageRepairRequestV3::decode(packet)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if request.mode() != mode
        || request.signed_intent() != intent
        || request.envelope() != envelope
        || request.expected_attestation_digest() != attestation
        || request.encode() != packet
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }

    Ok(())
}

fn terminal_phase(base: u8, epoch: u8) -> u8 { base + epoch * TERMINAL_EPOCH_STRIDE }

/// Joins full retained packets and original proposal DATA to a signed decision.
///
/// This historical check does not authenticate a live session or acquire hold
/// authority. The production driver separately reauthenticates all four originals.
///
/// # Errors
///
/// Rejects missing or substituted full packets, proposal, clock or decision sequence.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_failure_history_custody(
    journal: &Journal,
    operation: OperationId,
    signer: &ProtectedOperatorRecoverySignerV1,
    claims: &aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalRequestV4,
    before_digest: [u8; 32],
    after_digest: [u8; 32],
    completion_clock: i64,
    decision_sequence: u64,
) -> Result<aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalRequestV4, OperatorRecoveryIssuanceErrorV1> {
    let before = read_progress(journal, operation, BEFORE_PACKET)?
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let after = read_progress(journal, operation, AFTER_PACKET)?
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if hash(b"aos.sandbox.operator-storage-repair-before-packet.v1\0", &[before]) != before_digest
        || hash(b"aos.sandbox.operator-storage-repair-after-packet.v1\0", &[after]) != after_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    for epoch in 0..MAXIMUM_TERMINAL_EPOCHS {
        let Some(proposal) = read_progress(journal, operation, terminal_phase(HOLD_REQUEST, epoch))? else {
            continue;
        };
        let original = aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalRequestV4::verify(
            proposal.get(16..).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
            signer.verifier(), signer.generation(),
        ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if original.cut_digest() != claims.cut_digest() {
            continue;
        }
        let terminal = read_progress(journal, operation, terminal_phase(TERMINAL_PACKET, epoch))?
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if original.signed_intent() != claims.signed_intent()
            || original.signed_header()[444..588] != claims.signed_header()[444..588]
            || i64::from_be_bytes(super::take_array(proposal, 0)?) != completion_clock
            || u64::from_be_bytes(super::take_array(proposal, 8)?) > decision_sequence
            || original.signed_header()[460..492] != hash(
                b"aos.sandbox.operator-repair-terminal-fresh-packet.v1\0", &[terminal],
            )
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        return Ok(original);
    }
    Err(OperatorRecoveryIssuanceErrorV1::Binding)
}

fn read_progress(
    journal: &Journal,
    operation: OperationId,
    phase: u8,
) -> Result<Option<&[u8]>, OperatorRecoveryIssuanceErrorV1> {
    let key = progress_key(operation, phase);
    let Some(bytes) = journal.get(RecordNamespace::OperatorRecovery, &key) else {
        return Ok(None);
    };
    if bytes.len() < 36
        || &bytes[..8] != PROGRESS_MAGIC
        || &bytes[8..24] != operation.as_bytes()
        || bytes[24] != phase
        || bytes[25..32] != [0; 7]
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }

    let length = u32::from_be_bytes(super::take_array(bytes, 32)?) as usize;
    if bytes.len() != 36_usize.checked_add(length).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)? {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }

    Ok(Some(&bytes[36..]))
}

/// Checks scheduling debt without treating historical settlement as live heldness.
pub(super) fn has_settlement_debt(
    journal: &Journal,
    operation: OperationId,
) -> Result<bool, OperatorRecoveryIssuanceErrorV1> {
    journal.ensure_protected_authority().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let (signer, owner) = protected_query_roles()?;
    let mut debt = false;
    for epoch in 0..MAXIMUM_TERMINAL_EPOCHS {
        let hold = read_progress(journal, operation, terminal_phase(HOLD_REQUEST, epoch))?;
        let release = read_progress(journal, operation, terminal_phase(SETTLEMENT_READBACK, epoch))?;
        match (hold, release) {
            (None, None) => continue,
            (None, Some(_)) => return Err(OperatorRecoveryIssuanceErrorV1::Binding),
            (Some(proposal), release) => {
                let request = aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalRequestV4::verify(
                    proposal.get(16..).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
                    signer.verifier(), signer.generation(),
                ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
                let Some(release) = release else {
                    debt = true;
                    continue;
                };
                let ack = super::transport::verify_retained_terminal_readback_v4(
                    release, request.cut_digest(), &signer, &owner,
                )?;
                match ack.disposition() {
                    aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalDispositionV4::Committed => {
                        super::terminal::verify_settled_terminal_receipt_v2(
                            journal, &signer, &owner, operation, request.cut_digest(), ack.receipt_digest(),
                        )?;
                    }
                    aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalDispositionV4::OriginalPreconditionReplaced => {
                        super::terminal::verify_settled_failure_receipt_v1(
                            journal, &signer, &owner, operation, request.cut_digest(), ack.receipt_digest(),
                        )?;
                    }
                    aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalDispositionV4::NotCommitted => {}
                }
            }
        }
    }

    Ok(debt)
}

pub(super) fn verify_atomic_terminal_rows_v2(journal: &mut Journal, operation: OperationId) -> Result<super::RepairPublicTerminalV1, OperatorRecoveryIssuanceErrorV1> {
    let mut bridge = OperatorStorageRepairBridgeV1::claim(journal)?;
    let terminal = [b"storage-repair-terminal-v1/".as_slice(), operation.as_bytes()].concat();
    if bridge.journal.0.get(RecordNamespace::OperatorRecovery, &terminal)
        .is_some_and(|bytes| bytes.starts_with(b"AOSORF01"))
    {
        super::terminal::verify_current_failure_v1(bridge.journal.0, &bridge.signer,
            &bridge.owner, operation, None)?;
        return Ok(super::RepairPublicTerminalV1::OriginalPreconditionReplaced);
    }
    let (body, _) = bridge.original_request(operation)?;
    super::terminal::verify_current_terminal_v2(bridge.journal.0, &bridge.signer, &bridge.owner,
        operation, &body, None)?;
    Ok(super::RepairPublicTerminalV1::Succeeded)
}
