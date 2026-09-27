//! Root-owned capacity intent preceding a durable Source reservation.
//!
//! ```text
//! AOSQPI01 | version:u16=1 | reserved[6]=0 | client-nonce:16 |
//! project:16 | Source-reservation-digest:32 | project-packet:32 |
//! project-input:32 | deployment-packet:32 | prior-packet:32 |
//! prior-input:32 | capacity-reservation-id:32 |
//! SHA-256(Root-project-intent-domain || preceding 272 bytes):32
//! ```
//!
//! The capacity record is atomically written with this row. It reserves the
//! larger Root terminal or no-stage cancellation branch before Source writes
//! its reservation. The intent never asserts Source currentness or authorizes
//! policy admission.

use std::path::Path;

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
use super::super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::super::{
    PolicyDeploymentHeadErrorV1, PolicyDeploymentInputsV1, verify_policy_deployment_head_v1,
    verify_signed_project_policy_source_v2,
};
use super::{
    RESERVATION_CANCELLATION_DOMAIN, RootProjectAdmissionStageV1,
    RootProjectReservationCancellationV1, STAGE_KEY, digest, outcome_key,
    reservation_cancellation_key, zero_digest,
};

const KEY: &[u8] = b"\0aos-policy-project-admission-intent-v1\0";
const MAGIC: &[u8; 8] = b"AOSQPI01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-intent.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-intent-transaction.v1\0";
const BINDING_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-intent-binding.v1\0";
const CHAIN_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-intent-chain.v1\0";
const BYTES: usize = 304;

// The largest terminal writes V2 packet, input, outcome and capacity deletion.
// Every individual value remains bounded by the Root journal's 4 KiB record
// limit; 24 KiB covers record framing as well as either shorter abort branch.
const TERMINAL_RECORDS: u32 = 4;
const TERMINAL_BYTES: u64 = 24 * 1024;

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

    /// Returns the canonical protected Root row.
    #[must_use]
    pub fn record_bytes(self) -> [u8; BYTES] {
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
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(BINDING_DOMAIN)
                .chain_update(preimage)
                .finalize()
                .into(),
        )
    }

    fn transaction_id(self) -> [u8; 16] {
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.binding_digest().as_bytes())
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }

    fn capacity_request(self) -> GlobalCapacityReservationRequestV1 {
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
            owner_digest: *self.binding_digest().as_bytes(),
            operation_id: self.client_nonce,
            artifact_digest: *self.project_packet.as_bytes(),
            checkpoint_digest: *self.deployment_packet.as_bytes(),
            chain_head_digest: *chain.as_bytes(),
            terminal_records: TERMINAL_RECORDS,
            terminal_bytes: TERMINAL_BYTES,
            poison_records: TERMINAL_RECORDS,
            poison_bytes: TERMINAL_BYTES,
        }
    }

    fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
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
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..272])
            .finalize();
        bytes[272..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        if bytes.len() != BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
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
        };
        if row.client_nonce == [0; 16]
            || row.project.as_bytes() == &[0; 16]
            || row.source_reservation.as_bytes() == &[0; 32]
            || row.project_packet.as_bytes() == &[0; 32]
            || row.project_input.as_bytes() == &[0; 32]
            || row.deployment_packet.as_bytes() == &[0; 32]
            || (row.prior_packet.as_bytes() == &[0; 32]) != (row.prior_input.as_bytes() == &[0; 32])
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

pub(super) fn recover_current_intent_for_reservation_v1(
    source: SourceProjectAdmissionReservationV1,
) -> Result<Option<RootProjectAdmissionIntentV1>, PolicyDeploymentHeadErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
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
        return if capacity
            .lookup_global_capacity_reservation_v1(intent.capacity_id)?
            .is_none()
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
    Ok(())
}

pub(super) fn commit_reserved_terminal(
    journal: &mut Journal,
    expected: RootProjectAdmissionIntentV1,
    transaction: JournalTransaction,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    require_intent_capacity(journal, expected)?;
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

pub(super) fn require_stage_intent(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
    project_packet: &[u8],
    project_input: &[u8],
    deployment_packet: &[u8],
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let intent = current_intent(journal)?.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if intent.client_nonce != source.client_nonce()
        || intent.project != source.project()
        || intent.source_reservation != source.record_digest()
        || intent.project_packet != digest(project_packet)
        || intent.project_input != digest(project_input)
        || intent.deployment_packet != digest(deployment_packet)
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    require_intent_capacity(journal, intent)?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority
        .get(HEAD_KEY_V2)?
        .map(digest)
        .unwrap_or_else(zero_digest)
        != intent.prior_packet
        || authority
            .get(INPUT_KEY_V2)?
            .map(digest)
            .unwrap_or_else(zero_digest)
            != intent.prior_input
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(intent)
}

pub(super) fn require_terminal_intent(
    journal: &mut Journal,
    stage: RootProjectAdmissionStageV1,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let intent = current_intent(journal)?.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if intent.client_nonce != stage.client_nonce
        || intent.project != stage.project
        || intent.source_reservation != stage.source_reservation_digest
        || intent.project_packet != stage.packet_digest
        || intent.project_input != stage.input_digest
        || intent.deployment_packet != stage.deployment_digest
        || intent.prior_packet != stage.prior_packet_digest
        || intent.prior_input != stage.prior_input_digest
    {
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
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
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
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
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
        super::require_exact_root_outcome_state(
            stage,
            outcome,
            authority
                .get(HEAD_KEY_V2)?
                .map(digest)
                .unwrap_or_else(zero_digest),
            authority
                .get(INPUT_KEY_V2)?
                .map(digest)
                .unwrap_or_else(zero_digest),
        )?;
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
        super::require_exact_root_outcome_state(
            stage,
            outcome,
            authority
                .get(HEAD_KEY_V2)?
                .map(digest)
                .unwrap_or_else(zero_digest),
            authority
                .get(INPUT_KEY_V2)?
                .map(digest)
                .unwrap_or_else(zero_digest),
        )?;
    }
    drop(authority);
    if let Some(prior) = prior {
        if prior != marker {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        let capacity = journal.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::RootProjectAdmission,
        )?;
        if capacity
            .lookup_global_capacity_reservation_v1(intent.capacity_id)?
            .is_some()
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
    let capacity = journal.claim_global_capacity_reservation_authority(
        GlobalCapacityReservationPurposeV1::RootProjectAdmission,
    )?;
    if capacity
        .lookup_global_capacity_reservation_v1(intent.capacity_id)?
        .is_some()
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
    let intent = RootProjectAdmissionIntentV1 {
        client_nonce: source.client_nonce(),
        project: source.project(),
        source_reservation: source.record_digest(),
        project_packet: ObjectDigest::from_bytes([21; 32]),
        project_input: ObjectDigest::from_bytes([22; 32]),
        deployment_packet: ObjectDigest::from_bytes([23; 32]),
        prior_packet: zero_digest(),
        prior_input: zero_digest(),
        capacity_id: [0; 32],
    };
    commit_intent(journal, intent)
}

#[cfg(test)]
pub(super) fn prepare_test_exact_intent_with_journal(
    journal: &mut Journal,
    source: SourceProjectAdmissionReservationV1,
    project_packet: &[u8],
    project_input: &[u8],
    deployment_packet: &[u8],
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let intent = RootProjectAdmissionIntentV1 {
        client_nonce: source.client_nonce(),
        project: source.project(),
        source_reservation: source.record_digest(),
        project_packet: digest(project_packet),
        project_input: digest(project_input),
        deployment_packet: digest(deployment_packet),
        prior_packet: zero_digest(),
        prior_input: zero_digest(),
        capacity_id: [0; 32],
    };
    commit_intent(journal, intent)
}
