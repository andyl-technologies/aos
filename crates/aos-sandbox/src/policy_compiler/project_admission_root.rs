//! Root-owned single-flight stage for pre-Q04 explicit project admission.
//!
//! Root first reserves terminal/cancellation capacity for one prospective
//! Source row. Source then durably reserves that row under the
//! Controller-retained writer, and Root commits a stage bound to it, the
//! installed signed V2 packet/input, and its current predecessor before
//! yielding one nonce/cut. An unresolved or expired stage cannot be restaged;
//! Root must durably commit or abort it before a successor is issued.
//!
//! ```text
//! AOSQPS01 | version:u16=1 | reserved[6]=0 | client-nonce:16 |
//! Root-nonce:16 | Root-cut:32 | project:16 | V2-packet-digest:32 |
//! V2-input-digest:32 | deployment-digest:32 | prior-V2-packet-digest:32 |
//! prior-V2-input-digest:32 | Source-reservation-digest:32 |
//! issued-at:i64 | expires-at:i64 |
//! SHA-256(Root-project-stage-domain || preceding 304 bytes):32
//! ```

mod history;
mod intent;

pub(crate) use history::{
    ROOT_PROJECT_HISTORY_FLOOR_BYTES_V1,
    validate_capacity_settlement as validate_root_project_capacity_settlement_v1,
};
pub use history::{
    RootProjectHistoryFloorV1, RootProjectHistoryTerminalKindV1,
    fixed_root_project_history_readback_available_v1, recover_fixed_root_project_history_floor_v1,
    retire_fixed_root_project_history_v1,
};

pub(crate) use intent::{
    ROOT_PROJECT_ADMISSION_INTENT_BYTES_V2, ROOT_PROJECT_NEGATIVE_INTENT_BYTES_V1,
    validate_capacity_transfer as validate_root_project_capacity_transfer_v1,
};
#[cfg(test)]
mod positive_commit_fixture;

pub use intent::{
    RootProjectAdmissionIntentV1, fixed_root_project_negative_recovery_available_v1,
    prepare_fixed_root_project_admission_intent_v1, prepare_fixed_root_project_negative_intent_v1,
};
#[cfg(test)]
pub(crate) use positive_commit_fixture::signed_heads_for_project as test_signed_project_heads_for_history_v1;

use std::io;
use std::path::Path;

use aos_sandbox_core::model::{CacheDomainKind, RevocationPolicy};
use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalRecord, JournalTransaction, ProtectedJournalAuthority, RecordNamespace,
    SourceProjectAdmissionChallengeV1, SourceProjectAdmissionReservationV1,
};

use super::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use super::controller_hold_readback::PinnedControllerHoldSignerV1;
use super::controller_project_admission_readback::{
    ControllerProjectAdmissionChallengeV1, verify_controller_project_admission_readback_v1,
};
use super::controller_readback_session::fresh_root_nonce;
use super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::source_hold_pin::SOURCE_HOLD_PIN_KEY;
use super::source_hold_readback::{
    PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackChallengeV1,
};
use super::source_project_admission_readback::{
    verify_source_project_admission_readback_v1, verify_source_project_reservation_readback_v1,
    verify_source_project_retirement_readback_v1,
};
use super::{
    PolicyDeploymentHeadErrorV1, PolicyDeploymentInputsV1, verify_policy_deployment_head_v1,
    verify_signed_project_policy_source_v2,
};

const STAGE_KEY: &[u8] = b"\0aos-policy-project-admission-stage-v1\0";
const STAGE_MAGIC: &[u8; 8] = b"AOSQPS01";
const STAGE_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-stage.v1\0";
const STAGE_CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-cut.v1\0";
const STAGE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-project-admission-stage-transaction.v1\0";
const STAGE_BYTES: usize = 336;
const MAXIMUM_STAGE_SECONDS: i64 = 300;
const OUTCOME_PREFIX: &[u8] = b"\0aos-policy-project-admission-outcome-v1\0";
const OUTCOME_MAGIC: &[u8; 8] = b"AOSQPO01";
const OUTCOME_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-outcome.v1\0";
const OUTCOME_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-project-admission-outcome-transaction.v1\0";
const OUTCOME_BYTES: usize = 312;
const CLIENT_NONCE_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-client.v1\0";
const RESERVATION_CANCELLATION_PREFIX: &[u8] =
    b"\0aos-policy-project-reservation-cancellation-v1\0";
const RESERVATION_CANCELLATION_MAGIC: &[u8; 8] = b"AOSQPX01";
const RESERVATION_CANCELLATION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-project-reservation-cancellation.v1\0";
const RESERVATION_CANCELLATION_BYTES: usize = 112;

// This opener grants no caller-selected path or journal authority.
fn open_fixed_root_project_journal() -> Result<Journal, PolicyDeploymentHeadErrorV1> {
    let (journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    Ok(journal)
}

/// Retains Root's irreversible refusal to stage one Source reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProjectReservationCancellationV1 {
    reservation: ObjectDigest,
    client_nonce: [u8; 16],
    project: ProjectId,
}

impl RootProjectReservationCancellationV1 {
    #[cfg(test)]
    pub(crate) const fn from_test_claims(
        reservation: ObjectDigest,
        client_nonce: [u8; 16],
        project: ProjectId,
    ) -> Self {
        Self {
            reservation,
            client_nonce,
            project,
        }
    }

    /// Returns the exact Source reservation that Root will never stage.
    pub const fn reservation(self) -> ObjectDigest {
        self.reservation
    }

    /// Returns the effect-owned reservation nonce.
    pub const fn client_nonce(self) -> [u8; 16] {
        self.client_nonce
    }

    /// Returns the reserved project.
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the digest of the canonical durable cancellation row.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        digest(&self.encode())
    }

    /// Returns the canonical row for a fixed Root socket replay.
    #[must_use]
    pub fn record_bytes(self) -> [u8; RESERVATION_CANCELLATION_BYTES] {
        self.encode()
    }

    /// Decodes hostile bytes without authenticating Root custody.
    ///
    /// # Errors
    ///
    /// Rejects changed framing, claims, or checksum.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        Self::decode(bytes)
    }

    fn encode(self) -> [u8; RESERVATION_CANCELLATION_BYTES] {
        let mut bytes = [0; RESERVATION_CANCELLATION_BYTES];
        bytes[..8].copy_from_slice(RESERVATION_CANCELLATION_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(self.reservation.as_bytes());
        bytes[48..64].copy_from_slice(&self.client_nonce);
        bytes[64..80].copy_from_slice(self.project.as_bytes());
        let checksum = Sha256::new()
            .chain_update(RESERVATION_CANCELLATION_DOMAIN)
            .chain_update(&bytes[..80])
            .finalize();
        bytes[80..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        if bytes.len() != RESERVATION_CANCELLATION_BYTES
            || bytes.get(..8) != Some(RESERVATION_CANCELLATION_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        let row = Self {
            reservation: ObjectDigest::from_bytes(take::<32>(bytes, 16)?),
            client_nonce: take::<16>(bytes, 48)?,
            project: ProjectId::from_bytes(take::<16>(bytes, 64)?),
        };
        if row.reservation.as_bytes() == &[0; 32]
            || row.client_nonce == [0; 16]
            || row.project.as_bytes() == &[0; 16]
            || row.encode().as_slice() != bytes
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        Ok(row)
    }
}

fn reservation_cancellation_key(reservation: ObjectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(RESERVATION_CANCELLATION_PREFIX.len() + 32);
    key.extend_from_slice(RESERVATION_CANCELLATION_PREFIX);
    key.extend_from_slice(reservation.as_bytes());
    key
}

fn require_reservation_not_canceled(
    authority: &ProtectedJournalAuthority<'_>,
    reservation: ObjectDigest,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if authority
        .get(&reservation_cancellation_key(reservation))?
        .is_some()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_root_project_reservation_cancellation_v1(
    reservation: SourceProjectAdmissionReservationV1,
) -> RootProjectReservationCancellationV1 {
    RootProjectReservationCancellationV1 {
        reservation: reservation.record_digest(),
        client_nonce: reservation.client_nonce(),
        project: reservation.project(),
    }
}

/// Selects an immutable Root terminal outcome for one project-admission stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootProjectAdmissionOutcomeKindV1 {
    /// Root atomically admitted the exact signed V2 packet/input.
    Committed,
    /// Root durably abandoned the stage without changing the V2 head.
    Aborted,
}

/// Retains the exact terminal Root decision bound to a single stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProjectAdmissionOutcomeV1 {
    stage: ObjectDigest,
    kind: RootProjectAdmissionOutcomeKindV1,
    source_row: ObjectDigest,
    controller_packet: ObjectDigest,
    operation: [u8; 16],
    sandbox: [u8; 16],
    source_commitment: ObjectDigest,
    project: ProjectId,
    project_packet: ObjectDigest,
    project_input: ObjectDigest,
    client_nonce: [u8; 16],
}

impl RootProjectAdmissionOutcomeV1 {
    /// Returns the exact stage row digest consumed by this decision.
    #[must_use]
    pub const fn stage(self) -> ObjectDigest {
        self.stage
    }

    /// Returns the durable commit or abort result.
    #[must_use]
    pub const fn kind(self) -> RootProjectAdmissionOutcomeKindV1 {
        self.kind
    }

    /// Returns the challenged Source row digest, if one was spent.
    #[must_use]
    pub const fn source_row(self) -> ObjectDigest {
        self.source_row
    }

    /// Returns the admitted Controller source commitment on commit.
    #[must_use]
    pub const fn source_commitment(self) -> ObjectDigest {
        self.source_commitment
    }

    /// Returns the accepted Create operation on a committed outcome.
    #[must_use]
    pub const fn operation(self) -> [u8; 16] {
        self.operation
    }

    /// Returns the accepted Sandbox identity on a committed outcome.
    #[must_use]
    pub const fn sandbox(self) -> [u8; 16] {
        self.sandbox
    }

    /// Returns the exact project fixed by the stage.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the effect-owned stage nonce on either terminal outcome.
    #[must_use]
    pub const fn client_nonce(self) -> [u8; 16] {
        self.client_nonce
    }

    /// Returns the digest of the canonical Root outcome row.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        digest(&self.encode())
    }

    /// Returns the canonical outcome row for a peer-checked Root reply.
    #[must_use]
    pub fn record_bytes(self) -> [u8; OUTCOME_BYTES] {
        self.encode()
    }

    /// Decodes a hostile record without authenticating Root socket custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed status, missing claims, changed framing or checksum.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        Self::decode(bytes)
    }

    fn committed(
        stage: RootProjectAdmissionStageV1,
        source_row: ObjectDigest,
        controller_packet: ObjectDigest,
        operation: [u8; 16],
        sandbox: [u8; 16],
        source_commitment: ObjectDigest,
    ) -> Self {
        Self {
            stage: stage.record_digest(),
            kind: RootProjectAdmissionOutcomeKindV1::Committed,
            source_row,
            controller_packet,
            operation,
            sandbox,
            source_commitment,
            project: stage.project,
            project_packet: stage.packet_digest,
            project_input: stage.input_digest,
            client_nonce: stage.client_nonce,
        }
    }

    fn aborted(stage: RootProjectAdmissionStageV1, source_row: ObjectDigest) -> Self {
        Self {
            stage: stage.record_digest(),
            kind: RootProjectAdmissionOutcomeKindV1::Aborted,
            source_row,
            controller_packet: zero_digest(),
            operation: [0; 16],
            sandbox: [0; 16],
            source_commitment: zero_digest(),
            project: stage.project,
            project_packet: stage.packet_digest,
            project_input: stage.input_digest,
            client_nonce: stage.client_nonce,
        }
    }

    fn encode(self) -> [u8; OUTCOME_BYTES] {
        let mut bytes = [0; OUTCOME_BYTES];
        bytes[..8].copy_from_slice(OUTCOME_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(self.stage.as_bytes());
        bytes[48] = match self.kind {
            RootProjectAdmissionOutcomeKindV1::Committed => 1,
            RootProjectAdmissionOutcomeKindV1::Aborted => 2,
        };
        bytes[56..88].copy_from_slice(self.source_row.as_bytes());
        bytes[88..120].copy_from_slice(self.controller_packet.as_bytes());
        bytes[120..136].copy_from_slice(&self.operation);
        bytes[136..152].copy_from_slice(&self.sandbox);
        bytes[152..184].copy_from_slice(self.source_commitment.as_bytes());
        bytes[184..200].copy_from_slice(self.project.as_bytes());
        bytes[200..232].copy_from_slice(self.project_packet.as_bytes());
        bytes[232..264].copy_from_slice(self.project_input.as_bytes());
        bytes[264..280].copy_from_slice(&self.client_nonce);
        let checksum = Sha256::new()
            .chain_update(OUTCOME_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..280])
            .finalize();
        bytes[280..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        if bytes.len() != OUTCOME_BYTES
            || bytes.get(..8) != Some(OUTCOME_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
            || bytes[49..56] != [0; 7]
            || bytes[280..]
                != Sha256::new()
                    .chain_update(OUTCOME_CHECKSUM_DOMAIN)
                    .chain_update(&bytes[..280])
                    .finalize()[..]
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        let kind = match bytes[48] {
            1 => RootProjectAdmissionOutcomeKindV1::Committed,
            2 => RootProjectAdmissionOutcomeKindV1::Aborted,
            _ => return Err(PolicyDeploymentHeadErrorV1::InvalidHead),
        };
        let row = Self {
            stage: ObjectDigest::from_bytes(take::<32>(bytes, 16)?),
            kind,
            source_row: ObjectDigest::from_bytes(take::<32>(bytes, 56)?),
            controller_packet: ObjectDigest::from_bytes(take::<32>(bytes, 88)?),
            operation: take::<16>(bytes, 120)?,
            sandbox: take::<16>(bytes, 136)?,
            source_commitment: ObjectDigest::from_bytes(take::<32>(bytes, 152)?),
            project: ProjectId::from_bytes(take::<16>(bytes, 184)?),
            project_packet: ObjectDigest::from_bytes(take::<32>(bytes, 200)?),
            project_input: ObjectDigest::from_bytes(take::<32>(bytes, 232)?),
            client_nonce: take::<16>(bytes, 264)?,
        };
        let committed = kind == RootProjectAdmissionOutcomeKindV1::Committed;
        if row.stage.as_bytes() == &[0; 32]
            || row.project.as_bytes() == &[0; 16]
            || row.project_packet.as_bytes() == &[0; 32]
            || row.project_input.as_bytes() == &[0; 32]
            || row.client_nonce == [0; 16]
            || row.source_row.as_bytes() == &[0; 32]
            || committed && row.controller_packet.as_bytes() == &[0; 32]
            || committed && row.operation == [0; 16]
            || committed && row.sandbox == [0; 16]
            || committed && row.source_commitment.as_bytes() == &[0; 32]
            || !committed && row.controller_packet.as_bytes() != &[0; 32]
            || !committed && row.operation != [0; 16]
            || !committed && row.sandbox != [0; 16]
            || !committed && row.source_commitment.as_bytes() != &[0; 32]
            || row.encode().as_slice() != bytes
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        Ok(row)
    }
}

/// Derives an effect-stable stage nonce from the exact accepted Create source.
///
/// The Controller's protected selector establishes both inputs. Root checks
/// this derivation against the signed AOSCTP03 packet at final submission.
#[must_use]
pub fn project_admission_client_nonce_v1(
    operation: aos_sandbox_core::OperationId,
    source_commitment: ObjectDigest,
) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(CLIENT_NONCE_DOMAIN)
        .chain_update(operation.as_bytes())
        .chain_update(source_commitment.as_bytes())
        .finalize();
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&digest[..16]);
    nonce
}

fn outcome_key(stage: ObjectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(OUTCOME_PREFIX.len() + 32);
    key.extend_from_slice(OUTCOME_PREFIX);
    key.extend_from_slice(stage.as_bytes());
    key
}

/// Commits an explicit V2 project source under the Controller→Source→Root cut.
///
/// The Root service loads all signing keys, packets, and pins from its fixed
/// credentials and obtains the Source packet from its peer-checked signer
/// socket. Controller retains both writers through this Root-last CAS and
/// performs owner postflights before releasing them. Root verifies independent
/// signatures and stage-bound currentness; an outcome is atomically committed
/// with any changed V2 packet/input. This does not authorize Q04 or Create.
///
/// # Errors
///
/// Rejects stale stage, role pins, signed source, publisher/revocation claim,
/// Source ancestry/names, noncontiguous V2 generation, changed predecessor,
/// incomplete atomic commit, or unsafe Root custody.
#[allow(clippy::too_many_arguments)]
pub fn admit_fixed_root_project_source_from_owner_proofs_v1(
    stage_digest: ObjectDigest,
    controller_packet: &[u8],
    source_row_bytes: &[u8],
    source_packet: &[u8],
    controller_pin: &[u8],
    source_pin: &[u8],
    expected_controller_uid: u32,
    project_packet: &[u8],
    project_input: &[u8],
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    deployment_packet: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    deployment_key: &VerifyingKey,
    deployment_signer_generation: u64,
    now_unix_seconds: i64,
) -> Result<RootProjectAdmissionOutcomeV1, PolicyDeploymentHeadErrorV1> {
    admit_root_project_source_from_owner_proofs_with_journal(
        ProjectAdmissionJournalSource::fixed(),
        stage_digest,
        controller_packet,
        source_row_bytes,
        source_packet,
        controller_pin,
        source_pin,
        expected_controller_uid,
        project_packet,
        project_input,
        project_key,
        project_signer_generation,
        deployment_packet,
        deployment_inputs,
        deployment_key,
        deployment_signer_generation,
        now_unix_seconds,
    )
}

// The held variant is constructed only by the synthetic unit fixture. The
// production entry always opens its fixed Root owner after signature preflight.
struct ProjectAdmissionJournalSource<'a> {
    held: Option<&'a mut Journal>,
}

impl ProjectAdmissionJournalSource<'_> {
    fn fixed() -> Self {
        Self { held: None }
    }

    #[cfg(test)]
    fn held(journal: &mut Journal) -> ProjectAdmissionJournalSource<'_> {
        ProjectAdmissionJournalSource {
            held: Some(journal),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn admit_root_project_source_from_owner_proofs_with_journal(
    journal_source: ProjectAdmissionJournalSource<'_>,
    stage_digest: ObjectDigest,
    controller_packet: &[u8],
    source_row_bytes: &[u8],
    source_packet: &[u8],
    controller_pin: &[u8],
    source_pin: &[u8],
    expected_controller_uid: u32,
    project_packet: &[u8],
    project_input: &[u8],
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    deployment_packet: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    deployment_key: &VerifyingKey,
    deployment_signer_generation: u64,
    now_unix_seconds: i64,
) -> Result<RootProjectAdmissionOutcomeV1, PolicyDeploymentHeadErrorV1> {
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
    let controller_signer = PinnedControllerHoldSignerV1::decode(controller_pin)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let source_signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if expected_controller_uid == 0
        || project.head().deployment_signer_generation() != deployment_signer_generation
        || project.head().project_signer_generation() != project_signer_generation
        || project.head().prerequisite_claims()[1] != deployment.packet_digest()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }

    let source_row = SourceProjectAdmissionChallengeV1::from_record_bytes(source_row_bytes)?;
    let mut fixed_journal = if journal_source.held.is_some() {
        None
    } else {
        Some(open_fixed_root_project_journal()?)
    };
    let journal = match journal_source.held {
        Some(held) => held,
        None => fixed_journal
            .as_mut()
            .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?,
    };
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(pins.as_slice())
        || authority.get(HEAD_KEY)? != Some(deployment_packet)
        || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(controller_pin)
        || authority.get(SOURCE_HOLD_PIN_KEY)? != Some(source_pin)
        || authority.get(PROJECT_HEAD_KEY)?.is_some()
        || authority.get(PROJECT_INPUT_KEY)?.is_some()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::decode)
        .transpose()?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if stage.record_digest() != stage_digest
        || stage.project != project.head().project()
        || stage.packet_digest != project.head().packet_digest()
        || stage.input_digest != project.head().input_digest()
        || stage.deployment_digest != deployment.packet_digest()
        || !source_row.matches_current(
            stage.root_nonce,
            stage.cut,
            stage.project,
            project.head().prerequisite_claims()[0],
            stage_digest,
            source_row.names(),
        )
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let controller_challenge =
        ControllerProjectAdmissionChallengeV1::new(stage.root_nonce, stage.cut)
            .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let controller = verify_controller_project_admission_readback_v1(
        controller_packet,
        &controller_signer,
        controller_challenge,
        expected_controller_uid,
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let source_challenge = SourceHoldReadbackChallengeV1::new(stage.root_nonce, stage.cut)
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    verify_source_project_admission_readback_v1(
        source_packet,
        &source_signer,
        source_challenge,
        stage.project,
        source_row,
        stage.source_reservation_digest,
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if controller.project() != stage.project
        || controller.publisher_generation() != project.head().publisher_generation()
        || controller.publisher_digest() != project.head().publisher_digest()
        || controller.cache_domain_head() != project.head().prerequisite_claims()[2]
        || crate::publisher_policy::project_revocation_digest(
            stage.project,
            controller.revocation_scope(),
            controller.revocation_generation(),
        ) != project.head().prerequisite_claims()[3]
        || controller.revocation_head() != project.head().prerequisite_claims()[3]
        || RevocationPolicy::new(
            controller.revocation_mode(),
            controller.revocation_grace_nanos(),
        ) != project.revocation()
        || project.cache_domain().kind() != CacheDomainKind::Project
        || project.cache_domain().domain_id().as_bytes() != stage.project.as_bytes()
        || project_admission_client_nonce_v1(controller.operation(), controller.source_commitment())
            != stage.client_nonce
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }

    let outcome = RootProjectAdmissionOutcomeV1::committed(
        stage,
        source_row.record_digest(),
        digest(controller_packet),
        *controller.operation().as_bytes(),
        *controller.sandbox().as_bytes(),
        controller.source_commitment(),
    );
    let key = outcome_key(stage_digest);
    let prior_outcome = authority
        .get(&key)?
        .map(RootProjectAdmissionOutcomeV1::decode)
        .transpose()?;
    let prior_packet = authority.get(HEAD_KEY_V2)?;
    let prior_input = authority.get(INPUT_KEY_V2)?;
    if prior_packet.is_some() != prior_input.is_some() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let current_packet = prior_packet.map(digest).unwrap_or_else(zero_digest);
    let current_input = prior_input.map(digest).unwrap_or_else(zero_digest);
    if let Some(prior) = prior_outcome {
        require_exact_root_outcome_state(stage, prior, current_packet, current_input)?;
        return if prior == outcome {
            Ok(outcome)
        } else {
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        };
    }
    if now_unix_seconds < stage.issued_at
        || now_unix_seconds >= stage.expires_at
        || current_packet != stage.prior_packet_digest
        || current_input != stage.prior_input_digest
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let replay = prior_packet == Some(project_packet) && prior_input == Some(project_input);
    if !replay {
        let predecessor = prior_packet
            .zip(prior_input)
            .map(|(packet, input)| {
                let historical_time = i64::from_be_bytes(take::<8>(packet, 32)?);
                let previous = verify_signed_project_policy_source_v2(
                    packet,
                    input,
                    project_key,
                    historical_time,
                )?;
                if previous.head().project() != stage.project
                    || previous.head().deployment_signer_generation()
                        != deployment_signer_generation
                    || previous.head().project_signer_generation() != project_signer_generation
                {
                    return Err(PolicyDeploymentHeadErrorV1::StaleHead);
                }
                Ok(previous.head().generation())
            })
            .transpose()?
            .unwrap_or(0);
        if predecessor.checked_add(1) != Some(project.head().generation()) {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
    }
    let mut records = Vec::new();
    if !replay {
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            HEAD_KEY_V2.to_vec(),
            project_packet.to_vec(),
        ));
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            INPUT_KEY_V2.to_vec(),
            project_input.to_vec(),
        ));
    }
    let transaction = outcome_transaction(outcome, records)?;
    drop(authority);
    let intent = intent::require_terminal_intent(journal, stage)?;
    intent::commit_reserved_terminal(journal, intent, transaction)?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(&key)? != Some(outcome.encode().as_slice())
        || authority.get(HEAD_KEY_V2)? != Some(project_packet)
        || authority.get(INPUT_KEY_V2)? != Some(project_input)
        || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(controller_pin)
        || authority.get(SOURCE_HOLD_PIN_KEY)? != Some(source_pin)
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(outcome)
}

/// Durably aborts one exact Root stage without admitting a project source.
///
/// The Source row is untrusted input and is decoded and bound to the stage.
/// Abort without a durable Source challenge is not supported: a bare absence
/// observation could race challenge acquisition and strand the Source fence.
/// The separate Source writer accepts retirement only after peer-checked
/// replay of this exact Root outcome. Identical abort replay is idempotent.
///
/// # Errors
///
/// Rejects another stage, committed outcome, changed Source row, held Root
/// binding, changed V2 predecessor, or failed durable commit/readback.
pub fn abort_fixed_root_project_admission_v1(
    stage_digest: ObjectDigest,
    source_row_bytes: &[u8],
    source_packet: &[u8],
    source_pin: &[u8],
) -> Result<RootProjectAdmissionOutcomeV1, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if authority.get(SOURCE_HOLD_PIN_KEY)? != Some(source_pin) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::decode)
        .transpose()?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if stage.record_digest() != stage_digest {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let source_row = SourceProjectAdmissionChallengeV1::from_record_bytes(source_row_bytes)?;
    if source_row.project() != stage.project
        || source_row.nonce() != stage.root_nonce
        || source_row.cut() != stage.cut
        || source_row.stage() != stage_digest
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let challenge = SourceHoldReadbackChallengeV1::new(stage.root_nonce, stage.cut)
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    verify_source_project_retirement_readback_v1(
        source_packet,
        &signer,
        challenge,
        stage.project,
        source_row,
        stage.source_reservation_digest,
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let outcome = RootProjectAdmissionOutcomeV1::aborted(stage, source_row.record_digest());
    let key = outcome_key(stage_digest);
    if let Some(prior) = authority
        .get(&key)?
        .map(RootProjectAdmissionOutcomeV1::decode)
        .transpose()?
    {
        return if prior == outcome {
            Ok(outcome)
        } else {
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        };
    }
    let (current_packet, current_input) = current_project_head_digests(&authority)?;
    if current_packet != stage.prior_packet_digest || current_input != stage.prior_input_digest {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let transaction = outcome_transaction(outcome, Vec::new())?;
    drop(authority);
    let intent = intent::require_terminal_intent(&mut journal, stage)?;
    intent::commit_reserved_terminal(&mut journal, intent, transaction)?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(&key)? != Some(outcome.encode().as_slice()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(outcome)
}

/// Reads an immutable Root admission outcome by exact stage digest.
///
/// This root-owned readback does not authenticate transport to Controller;
/// only a fixed-socket peer check may mint a Source-retirement proof.
///
/// # Errors
///
/// Rejects malformed stage/outcome history or unsafe Root journal custody.
pub fn recover_fixed_root_project_admission_outcome_v1(
    stage_digest: ObjectDigest,
) -> Result<Option<RootProjectAdmissionOutcomeV1>, PolicyDeploymentHeadErrorV1> {
    if stage_digest.as_bytes() == &[0; 32] {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let mut journal = open_fixed_root_project_journal()?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let outcome = authority
        .get(&outcome_key(stage_digest))?
        .map(RootProjectAdmissionOutcomeV1::decode)
        .transpose()?;
    if outcome.is_some_and(|row| row.stage != stage_digest) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(outcome)
}

fn outcome_transaction(
    outcome: RootProjectAdmissionOutcomeV1,
    mut records: Vec<JournalRecord>,
) -> Result<JournalTransaction, PolicyDeploymentHeadErrorV1> {
    let bytes = outcome.encode();
    records.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        outcome_key(outcome.stage),
        bytes.to_vec(),
    ));
    let transaction_digest = Sha256::new()
        .chain_update(OUTCOME_TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let transaction_id: [u8; 16] = transaction_digest[..16]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    Ok(JournalTransaction::new(transaction_id, records)?)
}

/// Retains one Root-owned, exact signed-source admission challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProjectAdmissionStageV1 {
    client_nonce: [u8; 16],
    root_nonce: [u8; 16],
    cut: ObjectDigest,
    project: ProjectId,
    packet_digest: ObjectDigest,
    input_digest: ObjectDigest,
    deployment_digest: ObjectDigest,
    prior_packet_digest: ObjectDigest,
    prior_input_digest: ObjectDigest,
    source_reservation_digest: ObjectDigest,
    issued_at: i64,
    expires_at: i64,
}

impl RootProjectAdmissionStageV1 {
    /// Returns the effect-owned client nonce for exact retry.
    #[must_use]
    pub const fn client_nonce(self) -> [u8; 16] {
        self.client_nonce
    }

    /// Returns the Root-generated nonce spent by both owner proofs.
    #[must_use]
    pub const fn root_nonce(self) -> [u8; 16] {
        self.root_nonce
    }

    /// Returns the Root-owned signed-source cut.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }

    /// Returns the project fixed by the installed signed V2 packet.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the exact Source reservation admitted before this stage.
    #[must_use]
    pub const fn source_reservation_digest(self) -> ObjectDigest {
        self.source_reservation_digest
    }

    /// Returns the canonical digest of this exact stage row.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.encode()).into())
    }

    /// Returns the canonical stage row for a nonce-bound Root reply.
    #[must_use]
    pub fn record_bytes(self) -> [u8; STAGE_BYTES] {
        self.encode()
    }

    /// Decodes an untrusted stage; transport must authenticate Root separately.
    ///
    /// # Errors
    ///
    /// Rejects changed fields, checksum, lifetime, or Root cut.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        Self::decode(bytes)
    }

    /// Returns the exclusive stage expiry.
    #[must_use]
    pub const fn expires_at(self) -> i64 {
        self.expires_at
    }

    fn matches_request(
        self,
        client_nonce: [u8; 16],
        project: ProjectId,
        packet_digest: ObjectDigest,
        input_digest: ObjectDigest,
        deployment_digest: ObjectDigest,
        prior_packet_digest: ObjectDigest,
        prior_input_digest: ObjectDigest,
        source_reservation_digest: ObjectDigest,
    ) -> bool {
        self.client_nonce == client_nonce
            && self.project == project
            && self.packet_digest == packet_digest
            && self.input_digest == input_digest
            && self.deployment_digest == deployment_digest
            && self.prior_packet_digest == prior_packet_digest
            && self.prior_input_digest == prior_input_digest
            && self.source_reservation_digest == source_reservation_digest
    }

    fn encode(self) -> [u8; STAGE_BYTES] {
        let mut bytes = [0; STAGE_BYTES];
        bytes[..8].copy_from_slice(STAGE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.client_nonce);
        bytes[32..48].copy_from_slice(&self.root_nonce);
        bytes[48..80].copy_from_slice(self.cut.as_bytes());
        bytes[80..96].copy_from_slice(self.project.as_bytes());
        bytes[96..128].copy_from_slice(self.packet_digest.as_bytes());
        bytes[128..160].copy_from_slice(self.input_digest.as_bytes());
        bytes[160..192].copy_from_slice(self.deployment_digest.as_bytes());
        bytes[192..224].copy_from_slice(self.prior_packet_digest.as_bytes());
        bytes[224..256].copy_from_slice(self.prior_input_digest.as_bytes());
        bytes[256..288].copy_from_slice(self.source_reservation_digest.as_bytes());
        bytes[288..296].copy_from_slice(&self.issued_at.to_be_bytes());
        bytes[296..304].copy_from_slice(&self.expires_at.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(STAGE_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..304])
            .finalize();
        bytes[304..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        if bytes.len() != STAGE_BYTES
            || bytes.get(..8) != Some(STAGE_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
            || bytes[304..]
                != Sha256::new()
                    .chain_update(STAGE_CHECKSUM_DOMAIN)
                    .chain_update(&bytes[..304])
                    .finalize()[..]
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        let row = Self {
            client_nonce: take::<16>(bytes, 16)?,
            root_nonce: take::<16>(bytes, 32)?,
            cut: ObjectDigest::from_bytes(take::<32>(bytes, 48)?),
            project: ProjectId::from_bytes(take::<16>(bytes, 80)?),
            packet_digest: ObjectDigest::from_bytes(take::<32>(bytes, 96)?),
            input_digest: ObjectDigest::from_bytes(take::<32>(bytes, 128)?),
            deployment_digest: ObjectDigest::from_bytes(take::<32>(bytes, 160)?),
            prior_packet_digest: ObjectDigest::from_bytes(take::<32>(bytes, 192)?),
            prior_input_digest: ObjectDigest::from_bytes(take::<32>(bytes, 224)?),
            source_reservation_digest: ObjectDigest::from_bytes(take::<32>(bytes, 256)?),
            issued_at: i64::from_be_bytes(take::<8>(bytes, 288)?),
            expires_at: i64::from_be_bytes(take::<8>(bytes, 296)?),
        };
        if row.client_nonce == [0; 16]
            || row.root_nonce == [0; 16]
            || row.cut.as_bytes() == &[0; 32]
            || row.project.as_bytes() == &[0; 16]
            || row.packet_digest.as_bytes() == &[0; 32]
            || row.input_digest.as_bytes() == &[0; 32]
            || row.deployment_digest.as_bytes() == &[0; 32]
            || row.source_reservation_digest.as_bytes() == &[0; 32]
            || row.prior_packet_digest.as_bytes() == &[0; 32]
                && row.prior_input_digest.as_bytes() != &[0; 32]
            || row.prior_input_digest.as_bytes() == &[0; 32]
                && row.prior_packet_digest.as_bytes() != &[0; 32]
            || row.issued_at <= 0
            || row.expires_at <= row.issued_at
            || row.expires_at - row.issued_at > MAXIMUM_STAGE_SECONDS
            || row.cut != row.expected_cut()
            || row.encode().as_slice() != bytes
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        Ok(row)
    }

    fn expected_cut(self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(STAGE_CUT_DOMAIN)
                .chain_update(self.client_nonce)
                .chain_update(self.root_nonce)
                .chain_update(self.project.as_bytes())
                .chain_update(self.packet_digest.as_bytes())
                .chain_update(self.input_digest.as_bytes())
                .chain_update(self.deployment_digest.as_bytes())
                .chain_update(self.prior_packet_digest.as_bytes())
                .chain_update(self.prior_input_digest.as_bytes())
                .chain_update(self.source_reservation_digest.as_bytes())
                .chain_update(self.issued_at.to_be_bytes())
                .chain_update(self.expires_at.to_be_bytes())
                .finalize()
                .into(),
        )
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], PolicyDeploymentHeadErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)
}

fn root_nonce() -> Result<[u8; 16], PolicyDeploymentHeadErrorV1> {
    fresh_root_nonce().map_err(|error| {
        PolicyDeploymentHeadErrorV1::Journal(crate::journal::JournalError::Io(io::Error::other(
            error,
        )))
    })
}

/// Durably stages one installed signed V2 project source under Root custody.
///
/// The service must load all bytes and keys from its own fixed credentials.
/// Root verifies their journal-pinned roles and current deployment, then
/// rejects any unresolved stage, including an expired one. A retry with the
/// same client nonce and exact inputs receives the original nonce/cut.
///
/// # Errors
///
/// Rejects changed pins, stale deployment/project credentials, legacy state,
/// a held Q04 binding, another unresolved stage, expiry, or failed commit.
#[allow(clippy::too_many_arguments)]
pub fn stage_fixed_root_project_admission_v1(
    client_nonce: [u8; 16],
    project_packet: &[u8],
    project_input: &[u8],
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    deployment_packet: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    deployment_key: &VerifyingKey,
    deployment_signer_generation: u64,
    controller_pin: &[u8],
    source_pin: &[u8],
    source_reservation: SourceProjectAdmissionReservationV1,
    source_reservation_packet: &[u8],
    now_unix_seconds: i64,
) -> Result<RootProjectAdmissionStageV1, PolicyDeploymentHeadErrorV1> {
    if client_nonce == [0; 16] || now_unix_seconds <= 0 {
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
    if project.head().deployment_signer_generation() != deployment_signer_generation
        || project.head().project_signer_generation() != project_signer_generation
        || project.head().prerequisite_claims()[1] != deployment.packet_digest()
        || source_reservation.client_nonce() != client_nonce
        || source_reservation.project() != project.head().project()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let source_signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    verify_source_project_reservation_readback_v1(
        source_reservation_packet,
        &source_signer,
        source_reservation,
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;

    let mut journal = open_fixed_root_project_journal()?;
    intent::require_stage_intent(
        &mut journal,
        source_reservation,
        project_packet,
        project_input,
        deployment_packet,
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(pins.as_slice())
        || authority.get(HEAD_KEY)? != Some(deployment_packet)
        || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(controller_pin)
        || authority.get(SOURCE_HOLD_PIN_KEY)? != Some(source_pin)
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
    let predecessor_packet = prior_packet.map(digest).unwrap_or_else(zero_digest);
    let predecessor_input = prior_input.map(digest).unwrap_or_else(zero_digest);
    let packet_digest = project.head().packet_digest();
    let input_digest = project.head().input_digest();
    let deployment_digest = deployment.packet_digest();
    require_reservation_not_canceled(&authority, source_reservation.record_digest())?;

    if let Some(prior) = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::decode)
        .transpose()?
    {
        let key = outcome_key(prior.record_digest());
        let outcome = authority
            .get(&key)?
            .map(RootProjectAdmissionOutcomeV1::decode)
            .transpose()?;
        if let Some(outcome) = outcome {
            require_exact_root_outcome_state(
                prior,
                outcome,
                predecessor_packet,
                predecessor_input,
            )?;
            if prior.client_nonce == client_nonce
                && outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed
            {
                return Err(PolicyDeploymentHeadErrorV1::StaleHead);
            }
        } else {
            if !prior.matches_request(
                client_nonce,
                project.head().project(),
                packet_digest,
                input_digest,
                deployment_digest,
                predecessor_packet,
                predecessor_input,
                source_reservation.record_digest(),
            ) || now_unix_seconds >= prior.expires_at()
            {
                return Err(PolicyDeploymentHeadErrorV1::StaleHead);
            }
            return Ok(prior);
        }
    }
    let expires_at = now_unix_seconds
        .checked_add(MAXIMUM_STAGE_SECONDS)
        .map(|limit| {
            limit
                .min(deployment.expires_at())
                .min(project.head().expires_at())
        })
        .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)?;
    if expires_at <= now_unix_seconds {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let mut stage = RootProjectAdmissionStageV1 {
        client_nonce,
        root_nonce: root_nonce()?,
        cut: zero_digest(),
        project: project.head().project(),
        packet_digest,
        input_digest,
        deployment_digest,
        prior_packet_digest: predecessor_packet,
        prior_input_digest: predecessor_input,
        source_reservation_digest: source_reservation.record_digest(),
        issued_at: now_unix_seconds,
        expires_at,
    };
    stage.cut = stage.expected_cut();
    let transaction = stage_transaction(stage)?;
    let bytes = stage.encode();
    authority.commit(&transaction)?;
    if authority.get(STAGE_KEY)? != Some(bytes.as_slice()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(stage)
}

fn stage_transaction(
    stage: RootProjectAdmissionStageV1,
) -> Result<JournalTransaction, PolicyDeploymentHeadErrorV1> {
    let bytes = stage.encode();
    let transaction_digest = Sha256::new()
        .chain_update(STAGE_TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let transaction_id: [u8; 16] = transaction_digest[..16]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    Ok(JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            STAGE_KEY.to_vec(),
            bytes.to_vec(),
        )],
    )?)
}

/// Permanently rules out a Root stage for an unconsumed Source reservation.
///
/// Root consumes the capacity-backed intent for this exact prospective Source
/// row. Cancellation only denies a future stage; it makes no Source currentness
/// claim and therefore also works when Source could not append its row. Source
/// may retire a written reservation only after peer-checked marker readback.
///
/// # Errors
///
/// Rejects a missing or changed intent, an existing stage for this reservation,
/// changed Root custody, or failed reserved terminal commit.
pub fn cancel_fixed_root_project_reservation_v1(
    reservation: SourceProjectAdmissionReservationV1,
) -> Result<RootProjectReservationCancellationV1, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    cancel_root_project_reservation_with_journal_v1(reservation, &mut journal)
}

fn cancel_root_project_reservation_with_journal_v1(
    reservation: SourceProjectAdmissionReservationV1,
    journal: &mut Journal,
) -> Result<RootProjectReservationCancellationV1, PolicyDeploymentHeadErrorV1> {
    intent::cancel_reservation_with_journal(journal, reservation)
}

/// Durably cancels an unstaged Root project intent after service restart.
///
/// A staged intent is left for Source challenge/outcome recovery. Cancellation
/// of an unstaged intent is a denial only; Source may settle a reservation
/// written before the crash from the resulting exact Root marker.
///
/// # Errors
///
/// Rejects changed Root custody or an ambiguous reserved terminal write.
pub fn recover_fixed_root_unstaged_project_intent_v1() -> Result<(), PolicyDeploymentHeadErrorV1> {
    intent::cancel_current_unstaged_intent_v1()
}

/// Replays only an exact active Root intent for one prospective Source row.
///
/// This read-only query resolves a lost intent-prepare reply. A canceled row
/// returns no active intent; Controller must separately obtain its immutable
/// cancellation marker before it can advance the Source issue.
///
/// # Errors
///
/// Rejects malformed Root custody or an intent whose capacity disappeared
/// without an exact durable cancellation.
pub fn recover_fixed_root_project_admission_intent_v1(
    reservation: SourceProjectAdmissionReservationV1,
) -> Result<Option<RootProjectAdmissionIntentV1>, PolicyDeploymentHeadErrorV1> {
    intent::recover_current_intent_for_reservation_v1(reservation)
}

/// Reports whether protected Root history needs project-admission recovery.
///
/// A pending stage, retained intent, or historical terminal marker must remain
/// replayable even when current deployment credentials have expired. This
/// check grants no new admission or currentness authority.
///
/// # Errors
///
/// Rejects malformed protected history or unsafe Root journal custody.
pub fn fixed_root_project_admission_recovery_required_v1()
-> Result<bool, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    project_admission_recovery_required_with_journal(&mut journal)
}

fn project_admission_recovery_required_with_journal(
    journal: &mut Journal,
) -> Result<bool, PolicyDeploymentHeadErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::from_record_bytes)
        .transpose()?;
    let mut historical_terminal = false;
    for (key, value) in authority.records()? {
        if key.starts_with(OUTCOME_PREFIX) {
            let outcome = RootProjectAdmissionOutcomeV1::from_record_bytes(value)?;
            if key != outcome_key(outcome.stage()).as_slice() {
                return Err(PolicyDeploymentHeadErrorV1::StaleHead);
            }
            historical_terminal = true;
        } else if key.starts_with(RESERVATION_CANCELLATION_PREFIX) {
            let marker = RootProjectReservationCancellationV1::from_record_bytes(value)?;
            if key != reservation_cancellation_key(marker.reservation()).as_slice() {
                return Err(PolicyDeploymentHeadErrorV1::StaleHead);
            }
            historical_terminal = true;
        }
    }
    drop(authority);
    let intent = intent::current_intent(journal)?;
    Ok(stage.is_some() || intent.is_some() || historical_terminal)
}

/// Replays Root's historical Source-only signer pin for abort recovery.
///
/// The pin remains immutable in the protected Root journal. A current
/// credential file cannot replace it during an interrupted V2 flight.
///
/// # Errors
///
/// Rejects a malformed pin or unsafe Root journal custody.
pub fn recover_fixed_root_project_source_pin_v1()
-> Result<Option<Vec<u8>>, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    recover_project_source_pin_with_journal(&mut journal)
}

fn recover_project_source_pin_with_journal(
    journal: &mut Journal,
) -> Result<Option<Vec<u8>>, PolicyDeploymentHeadErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let pin = authority.get(SOURCE_HOLD_PIN_KEY)?.map(ToOwned::to_owned);
    if let Some(pin) = pin.as_deref() {
        PinnedSourceHoldReadbackSignerV1::decode(pin)
            .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    }
    Ok(pin)
}

/// Replays Root's exact durable refusal to stage one Source reservation.
///
/// # Errors
///
/// Rejects malformed history or unsafe Root journal custody.
pub fn recover_fixed_root_project_reservation_cancellation_v1(
    reservation: ObjectDigest,
) -> Result<Option<RootProjectReservationCancellationV1>, PolicyDeploymentHeadErrorV1> {
    if reservation.as_bytes() == &[0; 32] {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let mut journal = open_fixed_root_project_journal()?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let marker = authority
        .get(&reservation_cancellation_key(reservation))?
        .map(RootProjectReservationCancellationV1::decode)
        .transpose()?;
    if marker.is_some_and(|marker| marker.reservation() != reservation) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(marker)
}

/// Reads the exact current Root stage for a held Source signer flight.
///
/// # Errors
///
/// Rejects an absent or superseded stage, invalid row, or unsafe Root custody.
pub fn recover_fixed_root_project_admission_stage_v1(
    stage_digest: ObjectDigest,
) -> Result<RootProjectAdmissionStageV1, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::decode)
        .transpose()?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if stage.record_digest() != stage_digest {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(stage)
}

/// Reads the one unresolved Root stage for crash-safe Source-row creation.
///
/// A Controller that lost the stage reply can recover this exact row, create
/// its Source challenge under the retained Source writer, and durably abort
/// before attempting another Create. An expired stage remains recoverable.
///
/// # Errors
///
/// Rejects malformed stage/outcome history or unsafe Root journal custody.
pub fn recover_fixed_root_current_project_admission_stage_v1()
-> Result<Option<RootProjectAdmissionStageV1>, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let stage = authority
        .get(STAGE_KEY)?
        .map(RootProjectAdmissionStageV1::decode)
        .transpose()?;
    let Some(stage) = stage else {
        return Ok(None);
    };
    let outcome = authority
        .get(&outcome_key(stage.record_digest()))?
        .map(RootProjectAdmissionOutcomeV1::decode)
        .transpose()?;
    if let Some(outcome) = outcome {
        let (current_packet, current_input) = current_project_head_digests(&authority)?;
        require_exact_root_outcome_state(stage, outcome, current_packet, current_input)?;
        return Ok(None);
    }
    Ok(Some(stage))
}

// Reads packet before input from the same retained authority. Missing rows
// preserve the zero predecessor representation used by exact recovery.
fn current_project_head_digests(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<(ObjectDigest, ObjectDigest), PolicyDeploymentHeadErrorV1> {
    let packet = authority
        .get(HEAD_KEY_V2)?
        .map(digest)
        .unwrap_or_else(zero_digest);
    let input = authority
        .get(INPUT_KEY_V2)?
        .map(digest)
        .unwrap_or_else(zero_digest);
    Ok((packet, input))
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

fn zero_digest() -> ObjectDigest {
    ObjectDigest::from_bytes([0; 32])
}

#[cfg(test)]
pub(crate) fn test_source_project_admission_outcome_v1(
    row: SourceProjectAdmissionChallengeV1,
    stage: ObjectDigest,
) -> RootProjectAdmissionOutcomeV1 {
    RootProjectAdmissionOutcomeV1 {
        stage,
        kind: RootProjectAdmissionOutcomeKindV1::Aborted,
        source_row: row.record_digest(),
        controller_packet: zero_digest(),
        operation: [0; 16],
        sandbox: [0; 16],
        source_commitment: zero_digest(),
        project: row.project(),
        project_packet: ObjectDigest::from_bytes([2; 32]),
        project_input: ObjectDigest::from_bytes([3; 32]),
        client_nonce: [4; 16],
    }
}

fn require_exact_root_outcome_state(
    stage: RootProjectAdmissionStageV1,
    outcome: RootProjectAdmissionOutcomeV1,
    current_packet: ObjectDigest,
    current_input: ObjectDigest,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if outcome.stage != stage.record_digest()
        || outcome.project != stage.project
        || outcome.project_packet != stage.packet_digest
        || outcome.project_input != stage.input_digest
        || outcome.client_nonce != stage.client_nonce
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let expected = match outcome.kind {
        RootProjectAdmissionOutcomeKindV1::Committed => (stage.packet_digest, stage.input_digest),
        RootProjectAdmissionOutcomeKindV1::Aborted => {
            (stage.prior_packet_digest, stage.prior_input_digest)
        }
    };
    if (current_packet, current_input) != expected {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::lifecycle::protected_journal_join::source_domain_journal_limits;
    use crate::policy_compiler::encode_source_hold_readback_signer_credential_v1;

    #[test]
    fn root_startup_cancellation_precedes_source_reserve_and_forbids_late_stage() {
        let source_dir = tempfile::tempdir().unwrap();
        let root_dir = tempfile::tempdir().unwrap();
        for directory in [source_dir.path(), root_dir.path()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let uid = fs::metadata(source_dir.path()).unwrap().uid();
        let (mut source, _) = Journal::open_protected_at_uid(
            source_dir.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let names = source.protected_writer_physical_names_v1().unwrap();
        let reservation = source
            .preview_source_project_admission_reservation_v1(
                [1; 16],
                ProjectId::from_bytes([2; 16]),
                names,
            )
            .unwrap();
        let key = SigningKey::from_bytes(&[3; 32]);
        let pin =
            encode_source_hold_readback_signer_credential_v1(4, &key.verifying_key()).unwrap();

        let (mut root, _) = Journal::open_protected_at_uid(
            root_dir.path(),
            "policy-authority-v1.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .unwrap();
        let intent = intent::prepare_test_intent_with_journal(&mut root, reservation).unwrap();
        let before_query = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap()
            .snapshot()
            .unwrap()
            .sequence();
        assert_eq!(
            intent::recover_current_intent_with_journal(&mut root, reservation).unwrap(),
            Some(intent),
            "lost prepare ACK replays the exact active Root intent"
        );
        assert!(
            super::super::root_project_admission_proof::encode_root_project_intent_replay_reply_v1(
                reservation,
                Some(intent)
            )
            .is_err(),
            "V2 transport cannot repair legacy one-slot intent"
        );
        assert_eq!(
            root.claim_protected_authority(RecordNamespace::DesiredState)
                .unwrap()
                .snapshot()
                .unwrap()
                .sequence(),
            before_query,
            "intent requery must not append or advance Root custody"
        );
        let canonical = intent.record_bytes();
        assert_eq!(
            RootProjectAdmissionIntentV1::from_record_bytes(&canonical).unwrap(),
            intent
        );
        for offset in [0, 8, 16, 32, 48, 80, 112, 144, 176, 208, 240, 272] {
            let mut changed = canonical.clone();
            changed[offset] ^= 1;
            assert!(RootProjectAdmissionIntentV1::from_record_bytes(&changed).is_err());
        }
        intent::cancel_current_unstaged_intent_with_journal(&mut root).unwrap();
        assert_eq!(
            intent::recover_current_intent_with_journal(&mut root, reservation).unwrap(),
            None,
            "durable cancellation removes active intent authority"
        );
        let marker = cancel_root_project_reservation_with_journal_v1(reservation, &mut root)
            .expect("idempotent Root startup cancellation");
        assert!(intent::require_intent_capacity(&mut root, intent).is_err());

        let committed = source
            .record_source_project_admission_reservation_v1(
                reservation.client_nonce(),
                reservation.project(),
                names,
            )
            .expect("Source reservation racing Root startup cancellation");
        assert_eq!(committed, reservation);
        let packet = super::super::source_project_admission_readback::sign_source_project_reservation_fields_v1(
            committed, 4, &key,
        )
        .unwrap();
        let signer = PinnedSourceHoldReadbackSignerV1::decode(&pin).unwrap();
        verify_source_project_reservation_readback_v1(&packet, &signer, committed)
            .expect("valid signed Source replay cannot reopen canceled Root intent");
        let proof = super::super::root_project_admission_proof::RootProjectReservationCancellationProofV1::from_test_marker(marker);
        source
            .settle_source_project_admission_reservation_v1(committed, proof)
            .expect("Controller can retire the late Source row from Root's exact marker");
        assert!(
            source
                .preview_source_project_admission_reservation_v1(
                    committed.client_nonce(),
                    committed.project(),
                    names,
                )
                .is_err(),
            "legacy one-slot Root history cannot supply the required retirement ACK"
        );
        drop(root);

        let (mut cold, _) = Journal::open_protected_at_uid(
            root_dir.path(),
            "policy-authority-v1.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .unwrap();
        let authority = cold
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let replay = authority
            .get(&reservation_cancellation_key(reservation.record_digest()))
            .unwrap()
            .map(RootProjectReservationCancellationV1::decode)
            .transpose()
            .unwrap();
        assert_eq!(replay, Some(marker));
        assert!(
            require_reservation_not_canceled(&authority, reservation.record_digest(),).is_err()
        );
    }

    #[test]
    fn root_startup_cancellation_retires_already_committed_source_reservation() {
        let source_dir = tempfile::tempdir().unwrap();
        let root_dir = tempfile::tempdir().unwrap();
        for directory in [source_dir.path(), root_dir.path()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let uid = fs::metadata(source_dir.path()).unwrap().uid();
        let (mut source, _) = Journal::open_protected_at_uid(
            source_dir.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let names = source.protected_writer_physical_names_v1().unwrap();
        let preview = source
            .preview_source_project_admission_reservation_v1(
                [1; 16],
                ProjectId::from_bytes([2; 16]),
                names,
            )
            .unwrap();
        let (mut root, _) = Journal::open_protected_at_uid(
            root_dir.path(),
            "policy-authority-v1.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .unwrap();
        intent::prepare_test_intent_with_journal(&mut root, preview).unwrap();
        let reserved = source
            .record_source_project_admission_reservation_v1(
                preview.client_nonce(),
                preview.project(),
                names,
            )
            .unwrap();
        assert_eq!(reserved, preview);

        intent::cancel_current_unstaged_intent_with_journal(&mut root).unwrap();
        let marker = cancel_root_project_reservation_with_journal_v1(preview, &mut root).unwrap();
        let proof = super::super::root_project_admission_proof::RootProjectReservationCancellationProofV1::from_test_marker(marker);
        source
            .settle_source_project_admission_reservation_v1(preview, proof)
            .expect("exact peer-checked Root marker retires Source reservation");
        drop(source);

        let (cold, _) = Journal::open_protected_at_uid(
            source_dir.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        assert_eq!(
            cold.source_project_admission_reservation_status_v1()
                .unwrap(),
            Some((preview, true))
        );
    }

    #[test]
    fn retired_foreign_intent_cannot_reopen_after_successor_intent() {
        let source_dir = tempfile::tempdir().unwrap();
        let root_dir = tempfile::tempdir().unwrap();
        for directory in [source_dir.path(), root_dir.path()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let uid = fs::metadata(source_dir.path()).unwrap().uid();
        let (mut source, _) = Journal::open_protected_at_uid(
            source_dir.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let names = source.protected_writer_physical_names_v1().unwrap();
        let project = ProjectId::from_bytes([2; 16]);
        let prior = source
            .preview_source_project_admission_reservation_v1([1; 16], project, names)
            .unwrap();
        let successor = source
            .preview_source_project_admission_reservation_v1([3; 16], project, names)
            .unwrap();

        let (mut root, _) = Journal::open_protected_at_uid(
            root_dir.path(),
            "policy-authority-v1.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .unwrap();
        let prior_intent = intent::prepare_test_intent_with_journal(&mut root, prior).unwrap();
        let marker = cancel_root_project_reservation_with_journal_v1(prior, &mut root).unwrap();
        assert!(intent::require_intent_capacity(&mut root, prior_intent).is_err());
        let successor_intent =
            intent::prepare_test_intent_with_journal(&mut root, successor).unwrap();
        assert!(intent::require_intent_capacity(&mut root, successor_intent).is_ok());
        assert!(intent::require_stage_intent(&mut root, prior, &[21], &[22], &[23]).is_err());
        drop(root);

        let (mut cold, _) = Journal::open_protected_at_uid(
            root_dir.path(),
            "policy-authority-v1.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .unwrap();
        assert_eq!(
            cold.claim_protected_authority(RecordNamespace::DesiredState)
                .unwrap()
                .get(&reservation_cancellation_key(prior.record_digest()))
                .unwrap(),
            Some(marker.record_bytes().as_slice())
        );
        assert!(intent::require_intent_capacity(&mut cold, successor_intent).is_ok());
    }

    #[test]
    fn unrelated_root_writes_cannot_spend_cancellation_capacity() {
        let source_dir = tempfile::tempdir().unwrap();
        let root_dir = tempfile::tempdir().unwrap();
        for directory in [source_dir.path(), root_dir.path()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let uid = fs::metadata(root_dir.path()).unwrap().uid();
        let (mut source, _) = Journal::open_protected_at_uid(
            source_dir.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let names = source.protected_writer_physical_names_v1().unwrap();
        let reservation = source
            .preview_source_project_admission_reservation_v1(
                [1; 16],
                ProjectId::from_bytes([2; 16]),
                names,
            )
            .unwrap();
        let mut limits = policy_authority_journal_limits();
        limits.maximum_journal_bytes = 30 * 1024;
        let (mut root, _) = Journal::open_protected_at_uid(
            root_dir.path(),
            "policy-authority-v1.journal",
            limits,
            uid,
        )
        .unwrap();
        intent::prepare_test_intent_with_journal(&mut root, reservation).unwrap();

        let mut blocked = false;
        for index in 1_u8..16 {
            let transaction = JournalTransaction::new(
                [index; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    vec![index],
                    vec![index; 1024],
                )],
            )
            .unwrap();
            match root.commit(&transaction) {
                Ok(_) => {}
                Err(crate::journal::JournalError::LimitExceeded(
                    "outstanding global capacity reservations",
                )) => {
                    blocked = true;
                    break;
                }
                Err(other) => panic!("unexpected unrelated Root write failure: {other}"),
            }
        }
        assert!(
            blocked,
            "the finite Root journal must retain terminal headroom"
        );
        cancel_root_project_reservation_with_journal_v1(reservation, &mut root)
            .expect("logical capacity remains available for durable cancellation");
    }

    #[test]
    fn expired_deployment_keeps_exact_project_recovery_artifacts_replayable() {
        let signing_key = SigningKey::from_bytes(&[16; 32]);
        let inputs = ["AOSPNI01", "AOSPSI01", "AOSPBI01", "AOSPCI01"].map(|magic| {
            serde_json::to_vec(&serde_json::json!({
                "generation": 1,
                "input": {},
                "magic": magic,
            }))
            .unwrap()
        });
        let mut deployment = b"AOSPDH01".to_vec();
        deployment.extend_from_slice(&1_u64.to_be_bytes());
        deployment.extend_from_slice(&10_i64.to_be_bytes());
        deployment.extend_from_slice(&30_i64.to_be_bytes());
        for input in &inputs {
            deployment.extend_from_slice(&Sha256::digest(input));
        }
        let mut signed = b"aos.sandbox.policy-deployment-head.v1\0".to_vec();
        signed.extend_from_slice(&deployment);
        deployment.extend_from_slice(&signing_key.sign(&signed).to_bytes());
        let exact = PolicyDeploymentInputsV1 {
            node: &inputs[0],
            site: &inputs[1],
            backend: &inputs[2],
            catalogs: &inputs[3],
        };
        verify_policy_deployment_head_v1(&deployment, &exact, &signing_key.verifying_key(), 20)
            .expect("deployment valid before expiry");
        assert!(
            verify_policy_deployment_head_v1(&deployment, &exact, &signing_key.verifying_key(), 30)
                .is_err(),
            "the signed deployment head itself expires before recovery"
        );

        let stage = stage();
        let committed = RootProjectAdmissionOutcomeV1::committed(
            stage,
            ObjectDigest::from_bytes([9; 32]),
            ObjectDigest::from_bytes([10; 32]),
            [11; 16],
            [12; 16],
            ObjectDigest::from_bytes([13; 32]),
        );
        let aborted =
            RootProjectAdmissionOutcomeV1::aborted(stage, ObjectDigest::from_bytes([14; 32]));
        let marker = RootProjectReservationCancellationV1 {
            reservation: ObjectDigest::from_bytes([15; 32]),
            client_nonce: [16; 16],
            project: ProjectId::from_bytes([17; 16]),
        };
        for (key, value) in [
            (STAGE_KEY.to_vec(), stage.record_bytes().to_vec()),
            (
                outcome_key(committed.stage()),
                committed.record_bytes().to_vec(),
            ),
            (
                outcome_key(aborted.stage()),
                aborted.record_bytes().to_vec(),
            ),
            (
                reservation_cancellation_key(marker.reservation()),
                marker.record_bytes().to_vec(),
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let uid = fs::metadata(directory.path()).unwrap().uid();
            let (mut root, _) = Journal::open_protected_at_uid(
                directory.path(),
                "policy-authority-v1.journal",
                policy_authority_journal_limits(),
                uid,
            )
            .unwrap();
            assert!(!project_admission_recovery_required_with_journal(&mut root).unwrap());
            root.commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        key,
                        value,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
            drop(root);

            let (mut cold, _) = Journal::open_protected_at_uid(
                directory.path(),
                "policy-authority-v1.journal",
                policy_authority_journal_limits(),
                uid,
            )
            .unwrap();
            assert!(project_admission_recovery_required_with_journal(&mut cold).unwrap());
        }
    }

    #[test]
    fn historical_source_pin_replays_without_current_deployment_credentials() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut root, _) = Journal::open_protected_at_uid(
            directory.path(),
            "policy-authority-v1.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[13; 32]);
        let pin =
            encode_source_hold_readback_signer_credential_v1(14, &key.verifying_key()).unwrap();
        root.commit(
            &JournalTransaction::new(
                [15; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    SOURCE_HOLD_PIN_KEY.to_vec(),
                    pin.to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
        drop(root);

        let (mut cold, _) = Journal::open_protected_at_uid(
            directory.path(),
            "policy-authority-v1.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .unwrap();
        assert_eq!(
            recover_project_source_pin_with_journal(&mut cold).unwrap(),
            Some(pin.to_vec())
        );
    }

    fn stage() -> RootProjectAdmissionStageV1 {
        let mut stage = RootProjectAdmissionStageV1 {
            client_nonce: [1; 16],
            root_nonce: [2; 16],
            cut: zero_digest(),
            project: ProjectId::from_bytes([3; 16]),
            packet_digest: ObjectDigest::from_bytes([4; 32]),
            input_digest: ObjectDigest::from_bytes([5; 32]),
            deployment_digest: ObjectDigest::from_bytes([6; 32]),
            prior_packet_digest: zero_digest(),
            prior_input_digest: zero_digest(),
            source_reservation_digest: ObjectDigest::from_bytes([7; 32]),
            issued_at: 100,
            expires_at: 200,
        };
        stage.cut = stage.expected_cut();
        stage
    }

    #[test]
    fn root_stage_codec_rejects_changed_cut_predecessor_and_expiry() {
        let stage = stage();
        let bytes = stage.encode();
        assert_eq!(RootProjectAdmissionStageV1::decode(&bytes).unwrap(), stage);
        assert!(stage.matches_request(
            stage.client_nonce,
            stage.project,
            stage.packet_digest,
            stage.input_digest,
            stage.deployment_digest,
            stage.prior_packet_digest,
            stage.prior_input_digest,
            stage.source_reservation_digest,
        ));
        assert!(!stage.matches_request(
            [9; 16],
            stage.project,
            stage.packet_digest,
            stage.input_digest,
            stage.deployment_digest,
            stage.prior_packet_digest,
            stage.prior_input_digest,
            stage.source_reservation_digest,
        ));
        for offset in [16, 32, 48, 80, 96, 128, 160, 192, 224, 256, 288, 296, 304] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(RootProjectAdmissionStageV1::decode(&changed).is_err());
        }
    }

    #[test]
    fn reservation_cancellation_codec_binds_exact_source_row() {
        let marker = RootProjectReservationCancellationV1 {
            reservation: ObjectDigest::from_bytes([1; 32]),
            client_nonce: [2; 16],
            project: ProjectId::from_bytes([3; 16]),
        };
        let bytes = marker.record_bytes();
        assert_eq!(
            RootProjectReservationCancellationV1::from_record_bytes(&bytes).unwrap(),
            marker
        );
        for offset in [0, 8, 16, 48, 64, 80] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(RootProjectReservationCancellationV1::from_record_bytes(&changed).is_err());
        }
    }

    #[test]
    fn root_terminal_codec_distinguishes_atomic_commit_from_abort() {
        let stage = stage();
        let committed = RootProjectAdmissionOutcomeV1::committed(
            stage,
            ObjectDigest::from_bytes([10; 32]),
            ObjectDigest::from_bytes([11; 32]),
            [12; 16],
            [13; 16],
            ObjectDigest::from_bytes([14; 32]),
        );
        let aborted =
            RootProjectAdmissionOutcomeV1::aborted(stage, ObjectDigest::from_bytes([15; 32]));
        assert_eq!(
            RootProjectAdmissionOutcomeV1::decode(&committed.encode()).unwrap(),
            committed
        );
        assert_eq!(
            RootProjectAdmissionOutcomeV1::decode(&aborted.encode()).unwrap(),
            aborted
        );
        assert_ne!(committed.record_digest(), aborted.record_digest());
        for offset in [16, 48, 56, 88, 120, 136, 152, 184, 200, 232, 264, 280] {
            let mut changed = committed.encode();
            changed[offset] ^= 1;
            assert!(RootProjectAdmissionOutcomeV1::decode(&changed).is_err());
        }
    }
}
