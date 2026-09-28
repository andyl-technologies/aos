//! Root-owned capacity intent preceding a durable Source reservation.
//!
//! ```text
//! AOSQPI01 | version:u16=1, 2, or 3 | kind:u8 | reserved[5]=0 | client-nonce:16 |
//! project:16 | Source-reservation-digest:32 | project-packet:32 |
//! project-input:32 | deployment-packet:32 | prior-packet:32 |
//! prior-input:32 | capacity-reservation-id:32 |
//! V2/V3 only: remaining-records:u32 | reserved[4]=0 | remaining-bytes:u64 |
//! exact-terminal-digest:32 or zero |
//! V3 only: historical-Controller-dispatch-metadata:32 |
//! SHA-256(versioned-Root-project-intent-domain || preceding bytes):32
//! ```
//!
//! The capacity record is atomically written with this row. It reserves the
//! Root terminal and history-retirement suffix before Source writes its
//! reservation. Optional staging cannot consume that suffix. V1 retains its
//! original one-transaction behavior and cannot authorize history retirement.
//! The intent never asserts Source currentness or authorizes policy admission.
//! V3 has kind=1 and zero project-packet, project-input, deployment-packet;
//! V1/V2 have kind=0. V3 can only reserve cancellation/history retirement.

pub(super) mod negative;

pub use negative::{
    fixed_root_project_negative_recovery_available_v1,
    prepare_fixed_root_project_negative_intent_v1,
};

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, Journal, JournalRecord,
    JournalTransaction, RecordNamespace, SourceProjectAdmissionReservationV1,
    capacity_reservation_identity_is_exact_v1,
};

use super::super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::super::{
    PolicyDeploymentHeadErrorV1, PolicyDeploymentInputsV1, verify_policy_deployment_head_v1,
    verify_signed_project_policy_source_v2,
};
use super::{
    RESERVATION_CANCELLATION_DOMAIN, RootProjectAdmissionStageV1,
    RootProjectReservationCancellationV1, STAGE_KEY, current_project_head_digests, digest,
    open_fixed_root_project_journal, outcome_key, reservation_cancellation_key, zero_digest,
};

pub(super) const KEY: &[u8] = b"\0aos-policy-project-admission-intent-v1\0";
const MAGIC: &[u8; 8] = b"AOSQPI01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-intent.v1\0";
const CHECKSUM_DOMAIN_V2: &[u8] = b"aos.sandbox.policy-project-admission-intent.v2\0";
const CHECKSUM_DOMAIN_V3: &[u8] = b"aos.sandbox.policy-project-negative-intent.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-intent-transaction.v1\0";
const TRANSACTION_DOMAIN_V2: &[u8] =
    b"aos.sandbox.policy-project-admission-intent-transaction.v2\0";
const TRANSACTION_DOMAIN_V3: &[u8] = b"aos.sandbox.policy-project-negative-intent-transaction.v1\0";
const DECISION_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-decision.v1\0";
const BINDING_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-intent-binding.v1\0";
const NEGATIVE_BINDING_DOMAIN: &[u8] = b"aos.sandbox.policy-project-negative-intent-binding.v1\0";
const CHAIN_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-intent-chain.v1\0";
const BYTES_V1: usize = 304;
pub(crate) const ROOT_PROJECT_ADMISSION_INTENT_BYTES_V2: usize = 352;
pub(crate) const ROOT_PROJECT_NEGATIVE_INTENT_BYTES_V1: usize = 384;

// The largest terminal writes V2 packet, input, outcome and capacity deletion.
// Every individual value remains bounded by the Root journal's 4 KiB record
// limit; 24 KiB covers record framing as well as either shorter abort branch.
const TERMINAL_RECORDS: u32 = 4;
const TERMINAL_BYTES: u64 = 24 * 1024;
const SUFFIX_RECORDS: u32 = 11;
const SUFFIX_BYTES: u64 = 32 * 1024;

/// Retains Root's nonauthorizing, capacity-backed promise for one Source row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProjectAdmissionIntentV1 {
    client_nonce: [u8; 16],
    project: ProjectId,
    source_reservation: ObjectDigest,
    project_packet: ObjectDigest,
    project_input: ObjectDigest,
    deployment_packet: ObjectDigest,
    prior_packet: ObjectDigest,
    prior_input: ObjectDigest,
    capacity_id: [u8; 32],
    history_retirement: bool,
    remaining_records: u32,
    remaining_bytes: u64,
    decision: ObjectDigest,
    negative_dispatch: Option<ObjectDigest>,
}

impl RootProjectAdmissionIntentV1 {
    /// Returns the effect-stable client nonce.
    pub const fn client_nonce(self) -> [u8; 16] {
        self.client_nonce
    }

    /// Returns the exact prospective Source reservation digest.
    pub const fn source_reservation(self) -> ObjectDigest {
        self.source_reservation
    }

    /// Returns the project named by the Root credentials and Source preview.
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the capacity reservation that cannot be spent by another writer.
    pub const fn capacity_id(self) -> [u8; 32] {
        self.capacity_id
    }

    /// Reports a retirement-only intent that can never stage or commit policy.
    pub const fn is_retirement_only(self) -> bool {
        self.negative_dispatch.is_some()
    }

    pub(crate) const fn negative_dispatch_metadata(self) -> Option<ObjectDigest> {
        self.negative_dispatch
    }

    pub(super) const fn retains_history(self) -> bool {
        self.history_retirement
    }

    pub(super) const fn decision(self) -> ObjectDigest {
        self.decision
    }

    /// Returns the canonical protected Root row.
    #[must_use]
    pub fn record_bytes(self) -> Vec<u8> {
        self.encode()
    }

    /// Returns the digest of the canonical protected Root row.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        digest(&self.encode())
    }

    /// Decodes hostile bytes without authenticating Root custody.
    ///
    /// # Errors
    ///
    /// Rejects changed framing, fields, checksum, or capacity provenance.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        Self::decode(bytes)
    }

    fn binding_digest(self) -> ObjectDigest {
        let mut preimage = [0; 16 + 16 + 32 * 6];
        preimage[..16].copy_from_slice(&self.client_nonce);
        preimage[16..32].copy_from_slice(self.project.as_bytes());
        for (index, field) in [
            self.source_reservation,
            self.project_packet,
            self.project_input,
            self.deployment_packet,
            self.prior_packet,
            self.prior_input,
        ]
        .iter()
        .enumerate()
        {
            let start = 32 + index * 32;
            preimage[start..start + 32].copy_from_slice(field.as_bytes());
        }
        let mut hash = Sha256::new();
        hash.update(if self.is_retirement_only() {
            NEGATIVE_BINDING_DOMAIN
        } else {
            BINDING_DOMAIN
        });
        hash.update(preimage);
        if let Some(dispatch) = self.negative_dispatch {
            hash.update(dispatch.as_bytes());
        }
        ObjectDigest::from_bytes(hash.finalize().into())
    }

    fn matches_stage(self, stage: RootProjectAdmissionStageV1) -> bool {
        !self.is_retirement_only()
            && self.client_nonce == stage.client_nonce
            && self.project == stage.project
            && self.source_reservation == stage.source_reservation_digest
            && self.project_packet == stage.packet_digest
            && self.project_input == stage.input_digest
            && self.deployment_packet == stage.deployment_digest
            && self.prior_packet == stage.prior_packet_digest
            && self.prior_input == stage.prior_input_digest
    }

    fn decision_binding_digest(self) -> [u8; 32] {
        Sha256::new()
            .chain_update(DECISION_DOMAIN)
            .chain_update(self.binding_digest().as_bytes())
            .chain_update(self.decision.as_bytes())
            .finalize()
            .into()
    }

    fn transaction_id(self) -> [u8; 16] {
        let digest: [u8; 32] = if self.decision != zero_digest() {
            self.decision_binding_digest()
        } else {
            Sha256::new()
                .chain_update(if self.is_retirement_only() {
                    TRANSACTION_DOMAIN_V3
                } else if !self.history_retirement {
                    TRANSACTION_DOMAIN
                } else {
                    TRANSACTION_DOMAIN_V2
                })
                .chain_update(self.binding_digest().as_bytes())
                .finalize()
                .into()
        };
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }

    pub(super) fn capacity_request(self) -> GlobalCapacityReservationRequestV1 {
        let chain = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(CHAIN_DOMAIN)
                .chain_update(self.prior_packet.as_bytes())
                .chain_update(self.prior_input.as_bytes())
                .finalize()
                .into(),
        );
        GlobalCapacityReservationRequestV1 {
            purpose: GlobalCapacityReservationPurposeV1::RootProjectAdmission,
            owner_namespace: RecordNamespace::DesiredState,
            owner_id: *self.source_reservation.as_bytes(),
            owner_digest: if self.decision == zero_digest() {
                *self.binding_digest().as_bytes()
            } else {
                self.decision_binding_digest()
            },
            operation_id: self.client_nonce,
            artifact_digest: *if self.is_retirement_only() {
                self.source_reservation
            } else {
                self.project_packet
            }
            .as_bytes(),
            checkpoint_digest: *self
                .negative_dispatch
                .unwrap_or(self.deployment_packet)
                .as_bytes(),
            chain_head_digest: *chain.as_bytes(),
            future_transactions: if self.history_retirement && self.decision == zero_digest() {
                2
            } else {
                1
            },
            terminal_records: self.remaining_records,
            terminal_bytes: self.remaining_bytes,
            poison_records: self.remaining_records,
            poison_bytes: self.remaining_bytes,
        }
    }

    fn encode(self) -> Vec<u8> {
        let body_bytes = if self.is_retirement_only() {
            352
        } else if self.history_retirement {
            320
        } else {
            272
        };
        let mut bytes = vec![0; body_bytes + 32];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(
            &(if self.is_retirement_only() {
                3_u16
            } else if self.history_retirement {
                2_u16
            } else {
                1_u16
            })
            .to_be_bytes(),
        );
        bytes[10] = u8::from(self.is_retirement_only());
        bytes[16..32].copy_from_slice(&self.client_nonce);
        bytes[32..48].copy_from_slice(self.project.as_bytes());
        for (index, field) in [
            self.source_reservation,
            self.project_packet,
            self.project_input,
            self.deployment_packet,
            self.prior_packet,
            self.prior_input,
        ]
        .iter()
        .enumerate()
        {
            let start = 48 + index * 32;
            bytes[start..start + 32].copy_from_slice(field.as_bytes());
        }
        bytes[240..272].copy_from_slice(&self.capacity_id);
        if self.history_retirement {
            bytes[272..276].copy_from_slice(&self.remaining_records.to_be_bytes());
            bytes[280..288].copy_from_slice(&self.remaining_bytes.to_be_bytes());
            bytes[288..320].copy_from_slice(self.decision.as_bytes());
        }
        if let Some(dispatch) = self.negative_dispatch {
            bytes[320..352].copy_from_slice(dispatch.as_bytes());
        }
        let checksum = Sha256::new()
            .chain_update(if self.is_retirement_only() {
                CHECKSUM_DOMAIN_V3
            } else if self.history_retirement {
                CHECKSUM_DOMAIN_V2
            } else {
                CHECKSUM_DOMAIN
            })
            .chain_update(&bytes[..body_bytes])
            .finalize();
        bytes[body_bytes..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        let negative = bytes.len() == ROOT_PROJECT_NEGATIVE_INTENT_BYTES_V1
            && bytes.get(8..10) == Some(3_u16.to_be_bytes().as_slice())
            && bytes.get(10) == Some(&1);
        let history_retirement = negative
            || (bytes.len() == ROOT_PROJECT_ADMISSION_INTENT_BYTES_V2
                && bytes.get(8..10) == Some(2_u16.to_be_bytes().as_slice()));
        if (!history_retirement
            && (bytes.len() != BYTES_V1
                || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())))
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || (!negative && bytes.get(10) != Some(&0))
            || bytes.get(11..16) != Some([0; 5].as_slice())
            || (history_retirement && bytes[276..280] != [0; 4])
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        let field = |start: usize| -> Result<ObjectDigest, PolicyDeploymentHeadErrorV1> {
            Ok(ObjectDigest::from_bytes(super::take::<32>(bytes, start)?))
        };
        let row = Self {
            client_nonce: super::take::<16>(bytes, 16)?,
            project: ProjectId::from_bytes(super::take::<16>(bytes, 32)?),
            source_reservation: field(48)?,
            project_packet: field(80)?,
            project_input: field(112)?,
            deployment_packet: field(144)?,
            prior_packet: field(176)?,
            prior_input: field(208)?,
            capacity_id: super::take::<32>(bytes, 240)?,
            history_retirement,
            remaining_records: if history_retirement {
                u32::from_be_bytes(super::take::<4>(bytes, 272)?)
            } else {
                TERMINAL_RECORDS
            },
            remaining_bytes: if history_retirement {
                u64::from_be_bytes(super::take::<8>(bytes, 280)?)
            } else {
                TERMINAL_BYTES
            },
            decision: if history_retirement {
                field(288)?
            } else {
                zero_digest()
            },
            negative_dispatch: if negative { Some(field(320)?) } else { None },
        };
        if row.client_nonce == [0; 16]
            || row.project.as_bytes() == &[0; 16]
            || row.source_reservation.as_bytes() == &[0; 32]
            || [row.project_packet, row.project_input, row.deployment_packet]
                .iter()
                .any(|field| (field == &zero_digest()) != negative)
            || row
                .negative_dispatch
                .is_some_and(|field| field == zero_digest())
            || (row.prior_packet.as_bytes() == &[0; 32]) != (row.prior_input.as_bytes() == &[0; 32])
            || (history_retirement
                && (row.remaining_records == 0
                    || row.remaining_bytes == 0
                    || (row.decision == zero_digest()
                        && (row.remaining_records != SUFFIX_RECORDS
                            || row.remaining_bytes != SUFFIX_BYTES))
                    || (row.decision != zero_digest()
                        && (row.remaining_records >= SUFFIX_RECORDS
                            || row.remaining_bytes >= SUFFIX_BYTES))))
            || !capacity_reservation_identity_is_exact_v1(
                &row.capacity_request(),
                row.transaction_id(),
                row.capacity_id,
            )
            || row.encode().as_slice() != bytes
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        Ok(row)
    }
}

pub(super) fn current_intent(
    journal: &mut Journal,
) -> Result<Option<RootProjectAdmissionIntentV1>, PolicyDeploymentHeadErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    authority
        .get(KEY)?
        .map(RootProjectAdmissionIntentV1::decode)
        .transpose()
}

pub(super) fn current_intent_readback(
    journal: &Journal,
) -> Result<Option<RootProjectAdmissionIntentV1>, PolicyDeploymentHeadErrorV1> {
    journal.protected_writer_physical_names_v1()?;
    journal
        .get(RecordNamespace::DesiredState, KEY)
        .map(RootProjectAdmissionIntentV1::decode)
        .transpose()
}

pub(super) fn recover_current_intent_for_reservation_v1(
    source: SourceProjectAdmissionReservationV1,
) -> Result<Option<RootProjectAdmissionIntentV1>, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    recover_current_intent_with_journal(&mut journal, source)
}

pub(super) fn recover_current_intent_with_journal(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
) -> Result<Option<RootProjectAdmissionIntentV1>, PolicyDeploymentHeadErrorV1> {
    let Some(intent) = current_intent(journal)? else {
        return Ok(None);
    };
    if intent.client_nonce != source.client_nonce()
        || intent.project != source.project()
        || intent.source_reservation != source.record_digest()
    {
        return Ok(None);
    }

    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let marker = authority
        .get(&reservation_cancellation_key(intent.source_reservation))?
        .map(RootProjectReservationCancellationV1::from_record_bytes)
        .transpose()?;
    if let Some(marker) = marker {
        if marker.reservation() != intent.source_reservation
            || marker.client_nonce() != intent.client_nonce
            || marker.project() != intent.project
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        drop(authority);
        let capacity = journal.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::RootProjectAdmission,
        )?;
        let reserved = capacity
            .lookup_global_capacity_reservation_v1(intent.capacity_id)?
            .is_some();
        return if (!intent.history_retirement && !reserved)
            || (intent.history_retirement && reserved && intent.decision == marker.record_digest())
        {
            Ok(None)
        } else {
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        };
    }
    drop(authority);
    require_intent_capacity(journal, intent)?;
    Ok(Some(intent))
}

pub(super) fn require_intent_capacity(
    journal: &mut Journal,
    expected: RootProjectAdmissionIntentV1,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if current_intent(journal)? != Some(expected) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let authority = journal.claim_global_capacity_reservation_authority(
        GlobalCapacityReservationPurposeV1::RootProjectAdmission,
    )?;
    let reservation = authority.recover_global_capacity_reservation_v1(expected.capacity_id)?;
    if !reservation.matches_request(&expected.capacity_request(), expected.transaction_id()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    drop(authority);
    require_decision_state(journal, expected)?;
    Ok(())
}

fn require_decision_state(
    journal: &mut Journal,
    intent: RootProjectAdmissionIntentV1,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if intent.decision == zero_digest() {
        return Ok(());
    }
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if let Some(bytes) = authority.get(&reservation_cancellation_key(intent.source_reservation))? {
        let marker = RootProjectReservationCancellationV1::from_record_bytes(bytes)?;
        if marker.record_digest() != intent.decision
            || marker.project() != intent.project
            || marker.client_nonce() != intent.client_nonce
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        return Ok(());
    }
    if intent.is_retirement_only() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::decode)
        .transpose()?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let outcome = authority
        .get(&outcome_key(stage.record_digest()))?
        .map(super::RootProjectAdmissionOutcomeV1::decode)
        .transpose()?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if !intent.matches_stage(stage) || outcome.record_digest() != intent.decision {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let (packet, input) = current_project_head_digests(&authority)?;
    super::require_exact_root_outcome_state(stage, outcome, packet, input)
}

pub(super) fn commit_reserved_terminal(
    journal: &mut Journal,
    expected: RootProjectAdmissionIntentV1,
    transaction: JournalTransaction,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    require_intent_capacity(journal, expected)?;
    if expected.history_retirement {
        return commit_reserved_decision(journal, expected, transaction);
    }
    let mut capacity = journal.claim_global_capacity_reservation_authority(
        GlobalCapacityReservationPurposeV1::RootProjectAdmission,
    )?;
    let reservation = capacity.recover_global_capacity_reservation_v1(expected.capacity_id)?;
    let mut records = transaction.records().to_vec();
    records.push(reservation.settlement_record());
    let terminal = JournalTransaction::new(*transaction.id(), records)?;
    let preflight = capacity.preflight_reserved_terminal_v1(&reservation, &terminal)?;
    capacity.commit_reserved_terminal_v1(&preflight, reservation, &terminal)?;
    Ok(())
}

fn commit_reserved_decision(
    journal: &mut Journal,
    expected: RootProjectAdmissionIntentV1,
    transaction: JournalTransaction,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if expected.decision != zero_digest() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let decision = decision_digest(journal, expected, transaction.records())?;
    let old = journal.recover_global_capacity_reservation_v1(expected.capacity_id)?;
    let mut next = expected;
    next.decision = decision;
    next.remaining_records = expected
        .remaining_records
        .checked_sub(
            u32::try_from(transaction.records().len() + 3)
                .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?,
        )
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let id = next.transaction_id();

    // The capacity identity changes with its byte budget, but every encoded
    // field remains fixed width. Measure the exact canonical framed cut once,
    // then build the final smaller reservation and intent with that budget.
    let draft_capacity =
        journal.prepare_global_capacity_reservation_v1(next.capacity_request(), id)?;
    next.capacity_id = draft_capacity.reservation_id();
    let cut = decision_transaction(
        transaction.records(),
        old.settlement_record(),
        &draft_capacity,
        next,
    )?;
    let cost = crate::journal::encoded_transaction_append_bytes(&cut)?;
    next.remaining_bytes = expected
        .remaining_bytes
        .checked_sub(cost)
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let capacity = journal.prepare_global_capacity_reservation_v1(next.capacity_request(), id)?;
    next.capacity_id = capacity.reservation_id();
    let cut = decision_transaction(
        transaction.records(),
        old.settlement_record(),
        &capacity,
        next,
    )?;
    journal.transfer_root_project_capacity_v1(old, capacity, &cut)?;
    require_intent_capacity(journal, next)
}

fn decision_transaction(
    terminal: &[JournalRecord],
    deletion: JournalRecord,
    capacity: &crate::journal::PreparedGlobalCapacityReservationV1,
    intent: RootProjectAdmissionIntentV1,
) -> Result<JournalTransaction, PolicyDeploymentHeadErrorV1> {
    let mut records = terminal.to_vec();
    records.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        KEY.to_vec(),
        intent.encode(),
    ));
    records.push(deletion);
    records.push(capacity.record().clone());
    Ok(JournalTransaction::new(intent.transaction_id(), records)?)
}

/// Validates the exact owner cut behind Root's capacity-only mechanical swap.
pub(crate) fn validate_capacity_transfer(
    journal: &mut Journal,
    transaction: &JournalTransaction,
    old: &GlobalCapacityReservationRequestV1,
    new: &GlobalCapacityReservationRequestV1,
    old_id: [u8; 32],
    new_id: [u8; 32],
) -> Result<(), crate::journal::JournalError> {
    let mut check = || -> Result<(), PolicyDeploymentHeadErrorV1> {
        let prior = current_intent(journal)?.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
        let desired = transaction
            .records()
            .iter()
            .filter(|record| record.namespace() == RecordNamespace::DesiredState)
            .collect::<Vec<_>>();
        let (updated, terminal) = desired
            .split_last()
            .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
        if updated.key() != KEY {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        let next = RootProjectAdmissionIntentV1::decode(
            updated
                .value()
                .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?,
        )?;
        if transaction.records().len() != desired.len() + 2
            || prior.capacity_id != old_id
            || next.capacity_id != new_id
            || !prior.history_retirement
            || prior.decision != zero_digest()
            || next.decision == zero_digest()
            || prior.capacity_request() != *old
            || next.capacity_request() != *new
            || next.transaction_id() != *transaction.id()
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        let mut expected = prior;
        expected.decision = decision_digest(
            journal,
            prior,
            &terminal
                .iter()
                .map(|record| (*record).clone())
                .collect::<Vec<_>>(),
        )?;
        expected.capacity_id = new_id;
        expected.remaining_records = next.remaining_records;
        expected.remaining_bytes = next.remaining_bytes;
        if next != expected {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        Ok(())
    };
    check().map_err(|_| crate::journal::JournalError::AuthorityPreflightMismatch)
}

fn decision_digest(
    journal: &mut Journal,
    intent: RootProjectAdmissionIntentV1,
    records: &[JournalRecord],
) -> Result<ObjectDigest, PolicyDeploymentHeadErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let (current_packet, current_input) = current_project_head_digests(&authority)?;
    if current_packet != intent.prior_packet || current_input != intent.prior_input {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let terminal = records
        .last()
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if terminal.namespace() != RecordNamespace::DesiredState {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let bytes = terminal
        .value()
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if terminal.key() == reservation_cancellation_key(intent.source_reservation) {
        let marker = RootProjectReservationCancellationV1::from_record_bytes(bytes)?;
        if records.len() != 1
            || marker.reservation != intent.source_reservation
            || marker.project != intent.project
            || marker.client_nonce != intent.client_nonce
            || authority
                .get(STAGE_KEY)?
                .map(RootProjectAdmissionStageV1::decode)
                .transpose()?
                .is_some_and(|stage| stage.source_reservation_digest() == intent.source_reservation)
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        return Ok(marker.record_digest());
    }
    let stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::decode)
        .transpose()?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let outcome = super::RootProjectAdmissionOutcomeV1::from_record_bytes(bytes)?;
    if !intent.matches_stage(stage)
        || terminal.key() != outcome_key(stage.record_digest())
        || outcome.stage != stage.record_digest()
        || outcome.client_nonce != intent.client_nonce
        || outcome.project != intent.project
        || outcome.project_packet != intent.project_packet
        || outcome.project_input != intent.project_input
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    match &records[..records.len() - 1] {
        [] if outcome.kind == super::RootProjectAdmissionOutcomeKindV1::Aborted
            || (current_packet == intent.project_packet
                && current_input == intent.project_input) => {}
        [packet, input]
            if outcome.kind == super::RootProjectAdmissionOutcomeKindV1::Committed
                && packet.namespace() == RecordNamespace::DesiredState
                && packet.key() == HEAD_KEY_V2
                && packet.value().map(digest) == Some(intent.project_packet)
                && input.namespace() == RecordNamespace::DesiredState
                && input.key() == INPUT_KEY_V2
                && input.value().map(digest) == Some(intent.project_input) => {}
        _ => return Err(PolicyDeploymentHeadErrorV1::StaleHead),
    }
    Ok(outcome.record_digest())
}

pub(super) fn require_stage_intent(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
    project_packet: &[u8],
    project_input: &[u8],
    deployment_packet: &[u8],
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let intent = current_intent(journal)?.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if intent.is_retirement_only()
        || intent.client_nonce != source.client_nonce()
        || intent.project != source.project()
        || intent.source_reservation != source.record_digest()
        || intent.project_packet != digest(project_packet)
        || intent.project_input != digest(project_input)
        || intent.deployment_packet != digest(deployment_packet)
        || intent.decision != zero_digest()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    require_intent_capacity(journal, intent)?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let (packet, input) = current_project_head_digests(&authority)?;
    if packet != intent.prior_packet || input != intent.prior_input {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(intent)
}

pub(super) fn require_terminal_intent(
    journal: &mut Journal,
    stage: RootProjectAdmissionStageV1,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let intent = current_intent(journal)?.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if !intent.matches_stage(stage) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    require_intent_capacity(journal, intent)?;
    Ok(intent)
}

/// Commits a Root-owned capacity intent before Source reserves its row.
///
/// # Errors
///
/// Rejects stale credentials, a foreign outstanding intent, insufficient
/// journal capacity, or changed Root predecessor and protected custody.
#[allow(clippy::too_many_arguments)]
pub fn prepare_fixed_root_project_admission_intent_v1(
    source: SourceProjectAdmissionReservationV1,
    project_packet: &[u8],
    project_input: &[u8],
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    deployment_packet: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    deployment_key: &VerifyingKey,
    deployment_signer_generation: u64,
    now_unix_seconds: i64,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    if source.client_nonce() == [0; 16] {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let pins = encode_policy_signer_pins_v1(
        deployment_signer_generation,
        deployment_key,
        project_signer_generation,
        project_key,
    )?;
    let deployment = verify_policy_deployment_head_v1(
        deployment_packet,
        deployment_inputs,
        deployment_key,
        now_unix_seconds,
    )?;
    let project = verify_signed_project_policy_source_v2(
        project_packet,
        project_input,
        project_key,
        now_unix_seconds,
    )?;
    if project.head().project() != source.project()
        || project.head().deployment_signer_generation() != deployment_signer_generation
        || project.head().project_signer_generation() != project_signer_generation
        || project.head().prerequisite_claims()[1] != deployment.packet_digest()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let mut journal = open_fixed_root_project_journal()?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::history::require_successor_source_issue(&authority, source)?;
    super::super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(pins.as_slice())
        || authority.get(HEAD_KEY)? != Some(deployment_packet)
        || authority.get(PROJECT_HEAD_KEY)?.is_some()
        || authority.get(PROJECT_INPUT_KEY)?.is_some()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let prior_packet = authority.get(HEAD_KEY_V2)?;
    let prior_input = authority.get(INPUT_KEY_V2)?;
    if prior_packet.is_some() != prior_input.is_some() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let intent = RootProjectAdmissionIntentV1 {
        client_nonce: source.client_nonce(),
        project: source.project(),
        source_reservation: source.record_digest(),
        project_packet: digest(project_packet),
        project_input: digest(project_input),
        deployment_packet: digest(deployment_packet),
        prior_packet: prior_packet.map(digest).unwrap_or_else(zero_digest),
        prior_input: prior_input.map(digest).unwrap_or_else(zero_digest),
        capacity_id: [0; 32],
        history_retirement: true,
        remaining_records: SUFFIX_RECORDS,
        remaining_bytes: SUFFIX_BYTES,
        decision: zero_digest(),
        negative_dispatch: None,
    };
    let prior_intent = authority
        .get(KEY)?
        .map(RootProjectAdmissionIntentV1::decode)
        .transpose()?;
    let current_stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::from_record_bytes)
        .transpose()?;
    let current_outcome = current_stage
        .map(|stage| authority.get(&outcome_key(stage.record_digest())))
        .transpose()?
        .flatten()
        .map(super::RootProjectAdmissionOutcomeV1::from_record_bytes)
        .transpose()?;
    if let (Some(stage), None, Some(prior)) = (current_stage, current_outcome, prior_intent) {
        if stage.source_reservation_digest() != prior.source_reservation {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
    }
    if let (Some(stage), Some(outcome)) = (current_stage, current_outcome) {
        super::require_exact_root_outcome_state(
            stage,
            outcome,
            intent.prior_packet,
            intent.prior_input,
        )?;
    }
    if let Some(prior) = prior_intent {
        // Source cannot advance an issue until both owners accept Root's
        // history floor. Neither another nonce nor retry may orphan the
        // capacity-backed terminal still awaiting that floor.
        if prior.history_retirement && prior.decision != zero_digest() {
            drop(authority);
            require_intent_capacity(&mut journal, prior)?;
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        if prior.client_nonce == intent.client_nonce
            && prior.source_reservation == intent.source_reservation
            && prior.project == intent.project
            && prior.project_packet == intent.project_packet
            && prior.project_input == intent.project_input
            && prior.deployment_packet == intent.deployment_packet
            && prior.prior_packet == intent.prior_packet
            && prior.prior_input == intent.prior_input
        {
            drop(authority);
            require_intent_capacity(&mut journal, prior)?;
            return Ok(prior);
        }
        let prior_terminal = authority
            .get(&reservation_cancellation_key(prior.source_reservation))?
            .is_some()
            || current_stage.is_some_and(|stage| {
                stage.source_reservation_digest() == prior.source_reservation
                    && current_outcome.is_some()
            });
        if !prior_terminal {
            // A new effect cannot inherit or supersede this root-owned
            // capacity flight. First durably deny the old Source row; its
            // Controller may then settle from the exact Root marker.
            drop(authority);
            cancel_intent_with_journal(&mut journal, prior)?;
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
    }
    if current_stage.is_some() && current_outcome.is_none()
        || authority
            .get(&reservation_cancellation_key(source.record_digest()))?
            .is_some()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    drop(authority);

    commit_intent(&mut journal, intent)
}

fn commit_intent(
    journal: &mut Journal,
    mut intent: RootProjectAdmissionIntentV1,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let mut capacity = journal.claim_global_capacity_reservation_authority(
        GlobalCapacityReservationPurposeV1::RootProjectAdmission,
    )?;
    let prepared = capacity.prepare_global_capacity_reservation_v1(
        intent.capacity_request(),
        intent.transaction_id(),
    )?;
    intent.capacity_id = prepared.reservation_id();
    let bytes = intent.encode();
    let transaction = JournalTransaction::new(
        intent.transaction_id(),
        vec![
            JournalRecord::put(RecordNamespace::DesiredState, KEY.to_vec(), bytes.to_vec()),
            prepared.record().clone(),
        ],
    )?;
    let preflight = capacity.preflight_global_capacity_reservation_v1(&prepared, &transaction)?;
    let (_, reservation) =
        capacity.commit_global_capacity_reservation_v1(&preflight, prepared, &transaction)?;
    if reservation.reservation_id() != intent.capacity_id {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    drop(capacity);
    require_intent_capacity(journal, intent)?;
    Ok(intent)
}

pub(super) fn cancel_reservation_with_journal(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
) -> Result<RootProjectReservationCancellationV1, PolicyDeploymentHeadErrorV1> {
    let intent = current_intent(journal)?.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if intent.client_nonce != source.client_nonce()
        || intent.project != source.project()
        || intent.source_reservation != source.record_digest()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    cancel_intent_with_journal(journal, intent)
}

pub(super) fn cancel_current_unstaged_intent_v1() -> Result<(), PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    cancel_current_unstaged_intent_with_journal(&mut journal)
}

pub(super) fn cancel_current_unstaged_intent_with_journal(
    journal: &mut Journal,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    let Some(intent) = current_intent(journal)? else {
        return Ok(());
    };
    let capacity = journal.claim_global_capacity_reservation_authority(
        GlobalCapacityReservationPurposeV1::RootProjectAdmission,
    )?;
    let reserved = capacity
        .lookup_global_capacity_reservation_v1(intent.capacity_id)?
        .is_some();
    drop(capacity);
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::from_record_bytes)
        .transpose()?;
    let marker = authority
        .get(&reservation_cancellation_key(intent.source_reservation))?
        .map(RootProjectReservationCancellationV1::from_record_bytes)
        .transpose()?;
    let stage_outcome = stage
        .map(|stage| authority.get(&outcome_key(stage.record_digest())))
        .transpose()?
        .flatten()
        .map(super::RootProjectAdmissionOutcomeV1::from_record_bytes)
        .transpose()?;
    if let (Some(stage), Some(outcome)) = (stage, stage_outcome) {
        let (packet, input) = current_project_head_digests(&authority)?;
        super::require_exact_root_outcome_state(stage, outcome, packet, input)?;
    }
    if stage.is_some_and(|stage| {
        stage_outcome.is_none() && stage.source_reservation_digest() != intent.source_reservation
    }) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let terminal = marker.is_some_and(|marker| {
        marker.reservation() == intent.source_reservation
            && marker.client_nonce() == intent.client_nonce
            && marker.project() == intent.project
    }) || stage.is_some_and(|stage| {
        stage.source_reservation_digest() == intent.source_reservation
            && stage_outcome.is_some_and(|outcome| outcome.stage() == stage.record_digest())
    });
    if !reserved {
        return if terminal {
            Ok(())
        } else {
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        };
    }
    if terminal && intent.history_retirement {
        drop(authority);
        return require_intent_capacity(journal, intent);
    }
    if stage.is_some_and(|stage| stage.source_reservation_digest() == intent.source_reservation) {
        if stage_outcome.is_some() {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        return Ok(());
    }
    drop(authority);
    cancel_intent_with_journal(journal, intent)?;
    Ok(())
}

fn cancel_intent_with_journal(
    journal: &mut Journal,
    intent: RootProjectAdmissionIntentV1,
) -> Result<RootProjectReservationCancellationV1, PolicyDeploymentHeadErrorV1> {
    let marker = RootProjectReservationCancellationV1 {
        reservation: intent.source_reservation,
        client_nonce: intent.client_nonce,
        project: intent.project,
    };
    let key = reservation_cancellation_key(marker.reservation());
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if authority.get(KEY)? != Some(intent.encode().as_slice()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let prior = authority
        .get(&key)?
        .map(RootProjectReservationCancellationV1::from_record_bytes)
        .transpose()?;
    let current_stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::from_record_bytes)
        .transpose()?;
    if let Some(stage) = current_stage {
        if stage.source_reservation_digest() == intent.source_reservation {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        let outcome = authority
            .get(&outcome_key(stage.record_digest()))?
            .map(super::RootProjectAdmissionOutcomeV1::from_record_bytes)
            .transpose()?;
        let outcome = outcome.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
        let (packet, input) = current_project_head_digests(&authority)?;
        super::require_exact_root_outcome_state(stage, outcome, packet, input)?;
    }
    drop(authority);
    if let Some(prior) = prior {
        if prior != marker {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        let capacity = journal.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::RootProjectAdmission,
        )?;
        let reserved = capacity
            .lookup_global_capacity_reservation_v1(intent.capacity_id)?
            .is_some();
        if (!intent.history_retirement && reserved)
            || (intent.history_retirement
                && (!reserved || intent.decision != marker.record_digest()))
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        return Ok(marker);
    }

    let bytes = marker.record_bytes();
    let transaction_digest = Sha256::new()
        .chain_update(RESERVATION_CANCELLATION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&transaction_digest[..16]);
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            key.clone(),
            bytes.to_vec(),
        )],
    )?;
    commit_reserved_terminal(journal, intent, transaction)?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(&key)? != Some(bytes.as_slice()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    drop(authority);
    let current = current_intent(journal)?.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let capacity = journal.claim_global_capacity_reservation_authority(
        GlobalCapacityReservationPurposeV1::RootProjectAdmission,
    )?;
    let reserved = capacity
        .lookup_global_capacity_reservation_v1(current.capacity_id)?
        .is_some();
    if (!intent.history_retirement && reserved)
        || (intent.history_retirement && (!reserved || current.decision != marker.record_digest()))
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(marker)
}

#[cfg(test)]
pub(super) fn prepare_test_intent_with_journal(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    prepare_test_intent_with_digests(
        journal,
        source,
        ObjectDigest::from_bytes([21; 32]),
        ObjectDigest::from_bytes([22; 32]),
        ObjectDigest::from_bytes([23; 32]),
        false,
    )
}

#[cfg(test)]
pub(super) fn prepare_test_exact_intent_with_journal(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
    project_packet: &[u8],
    project_input: &[u8],
    deployment_packet: &[u8],
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    prepare_test_intent_with_digests(
        journal,
        source,
        digest(project_packet),
        digest(project_input),
        digest(deployment_packet),
        false,
    )
}

#[cfg(test)]
pub(super) fn prepare_test_exact_history_intent_with_journal(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
    project_packet: &[u8],
    project_input: &[u8],
    deployment_packet: &[u8],
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    prepare_test_intent_with_digests(
        journal,
        source,
        digest(project_packet),
        digest(project_input),
        digest(deployment_packet),
        true,
    )
}

#[cfg(test)]
fn prepare_test_intent_with_digests(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
    project_packet: ObjectDigest,
    project_input: ObjectDigest,
    deployment_packet: ObjectDigest,
    history_retirement: bool,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let intent = RootProjectAdmissionIntentV1 {
        client_nonce: source.client_nonce(),
        project: source.project(),
        source_reservation: source.record_digest(),
        project_packet,
        project_input,
        deployment_packet,
        prior_packet: zero_digest(),
        prior_input: zero_digest(),
        capacity_id: [0; 32],
        history_retirement,
        remaining_records: if history_retirement {
            SUFFIX_RECORDS
        } else {
            TERMINAL_RECORDS
        },
        remaining_bytes: if history_retirement {
            SUFFIX_BYTES
        } else {
            TERMINAL_BYTES
        },
        decision: zero_digest(),
        negative_dispatch: None,
    };
    commit_intent(journal, intent)
}

#[cfg(test)]
pub(super) fn prepare_test_retirement_intent_with_journal(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    prepare_test_intent_with_digests(
        journal,
        source,
        ObjectDigest::from_bytes([21; 32]),
        ObjectDigest::from_bytes([22; 32]),
        ObjectDigest::from_bytes([23; 32]),
        true,
    )
}
