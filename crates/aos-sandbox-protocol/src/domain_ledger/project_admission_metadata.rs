//! Canonical nonauthorizing metadata retained in the original Controller Effect.
//!
//! Decoding preserves historical bytes only. The parent module owns protected
//! admission joins, capacity transfers, authenticated Root proofs, and Source ACK.
//!
//! ```text
//! AOSCPT01 | version:u16 | phase:u8 | terminal-kind:u8 | projection-length:u32 |
//! admission-revision:32 | admission-generation:u64 | source-commitment:32 |
//! sandbox:16 | project:16 | capacity-id:32 | Source-reservation[136] |
//! Source-challenge[232] or zero | Root-terminal[312] or zero |
//! historical-source-heads[160] | retired-floor-digest:32 or zero |
//! immutable-original-AOSPRJ01[projection-length] | domain-separated-checksum:32
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId, SandboxId};
use sha2::{Digest as _, Sha256};

use super::project_source::HistoricalCreateProjectSourceHeadsV1;
use super::root_project_history::{
    RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeV1, RootProjectHistoryFloorV1,
    RootProjectHistoryTerminalKindV1, RootProjectReservationCancellationV1,
};
use super::source_project_history::{
    SourceProjectAdmissionChallengeKindV1, SourceProjectAdmissionChallengeV1,
    SourceProjectAdmissionReservationV1,
};

#[derive(Debug, thiserror::Error)]
pub enum ProjectAdmissionMetadataDataErrorV1 {
    #[error("invalid Controller project-admission metadata")]
    InvalidMetadata,
}

const MAXIMUM_RETAINED_PUBLIC_PROJECTION_BYTES: usize =
    96 + crate::public_api::MAXIMUM_PUBLIC_RESOURCE_BYTES;

const MAGIC: &[u8; 8] = b"AOSCPT01";
const DOMAIN: &[u8] = b"aos.sandbox.controller-project-terminal-metadata.v1\0";
const FIXED_BODY_BYTES: usize = 1024;
pub const MAXIMUM_RECORD_BYTES: usize =
    FIXED_BODY_BYTES + MAXIMUM_RETAINED_PUBLIC_PROJECTION_BYTES + 32;


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProjectAdmissionPhaseV1 {
    Prepared = 1,
    DispatchAuthorized = 2,
    AcceptedRootTerminal = 3,
    RootRetired = 4,
}

/// Stores historical bytes, never a transport-authenticated terminal proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedRootProjectTerminalV1 {
    Outcome(RootProjectAdmissionOutcomeV1),
    Cancellation(RootProjectReservationCancellationV1),
}

impl RetainedRootProjectTerminalV1 {
    pub fn kind(self) -> RootProjectHistoryTerminalKindV1 {
        match self {
            Self::Outcome(row) if row.kind() == RootProjectAdmissionOutcomeKindV1::Committed => {
                RootProjectHistoryTerminalKindV1::Committed
            }
            Self::Outcome(_) => RootProjectHistoryTerminalKindV1::Aborted,
            Self::Cancellation(_) => RootProjectHistoryTerminalKindV1::CanceledReservation,
        }
    }

    pub fn record_digest(self) -> ObjectDigest {
        match self {
            Self::Outcome(row) => row.record_digest(),
            Self::Cancellation(row) => row.record_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectAdmissionMetadataV1 {
    admission_revision: ObjectDigest,
    admission_generation: u64,
    source_commitment: ObjectDigest,
    sandbox: SandboxId,
    project: ProjectId,
    reservation: SourceProjectAdmissionReservationV1,
    capacity_id: [u8; 32],
    phase: ProjectAdmissionPhaseV1,
    challenge: Option<SourceProjectAdmissionChallengeV1>,
    terminal: Option<RetainedRootProjectTerminalV1>,
    retired_floor: Option<ObjectDigest>,
    source_heads: HistoricalCreateProjectSourceHeadsV1,
    original_projection: Vec<u8>,
}

impl ProjectAdmissionMetadataV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_historical_fields(
        admission_revision: ObjectDigest,
        admission_generation: u64,
        source_commitment: ObjectDigest,
        sandbox: SandboxId,
        project: ProjectId,
        reservation: SourceProjectAdmissionReservationV1,
        capacity_id: [u8; 32],
        phase: ProjectAdmissionPhaseV1,
        challenge: Option<SourceProjectAdmissionChallengeV1>,
        terminal: Option<RetainedRootProjectTerminalV1>,
        retired_floor: Option<ObjectDigest>,
        source_heads: HistoricalCreateProjectSourceHeadsV1,
        original_projection: Vec<u8>,
    ) -> Self {
        Self {
            admission_revision,
            admission_generation,
            source_commitment,
            sandbox,
            project,
            reservation,
            capacity_id,
            phase,
            challenge,
            terminal,
            retired_floor,
            source_heads,
            original_projection,
        }
    }

    pub const fn admission_revision(&self) -> ObjectDigest {
        self.admission_revision
    }

    pub const fn admission_generation(&self) -> u64 {
        self.admission_generation
    }

    pub const fn source_commitment(&self) -> ObjectDigest {
        self.source_commitment
    }

    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    pub const fn project(&self) -> ProjectId {
        self.project
    }

    pub const fn reservation(&self) -> SourceProjectAdmissionReservationV1 {
        self.reservation
    }

    pub const fn capacity_id(&self) -> [u8; 32] {
        self.capacity_id
    }

    pub const fn phase(&self) -> ProjectAdmissionPhaseV1 {
        self.phase
    }

    pub const fn challenge(&self) -> Option<SourceProjectAdmissionChallengeV1> {
        self.challenge
    }

    pub const fn terminal(&self) -> Option<RetainedRootProjectTerminalV1> {
        self.terminal
    }

    pub const fn retired_floor(&self) -> Option<ObjectDigest> {
        self.retired_floor
    }

    pub const fn source_heads(&self) -> HistoricalCreateProjectSourceHeadsV1 {
        self.source_heads
    }

    pub fn original_projection(&self) -> &[u8] {
        &self.original_projection
    }

    pub fn set_historical_capacity_id(&mut self, capacity_id: [u8; 32]) {
        self.capacity_id = capacity_id;
    }

    pub fn set_historical_phase(&mut self, phase: ProjectAdmissionPhaseV1) {
        self.phase = phase;
    }

    pub fn set_historical_challenge(&mut self, challenge: Option<SourceProjectAdmissionChallengeV1>) {
        self.challenge = challenge;
    }

    pub fn set_historical_terminal(&mut self, terminal: Option<RetainedRootProjectTerminalV1>) {
        self.terminal = terminal;
    }

    pub fn set_historical_retired_floor(&mut self, retired_floor: Option<ObjectDigest>) {
        self.retired_floor = retired_floor;
    }


    pub fn acceptance_digest(&self) -> Result<ObjectDigest, ProjectAdmissionMetadataDataErrorV1> {
        if !matches!(
            self.phase,
            ProjectAdmissionPhaseV1::AcceptedRootTerminal | ProjectAdmissionPhaseV1::RootRetired
        ) {
            return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
        }
        let accepted = Self {
            phase: ProjectAdmissionPhaseV1::AcceptedRootTerminal,
            retired_floor: None,
            ..self.clone()
        };
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(accepted.encode()?).into(),
        ))
    }

    pub fn matches_floor(
        &self,
        operation: aos_sandbox_core::OperationId,
        floor: RootProjectHistoryFloorV1,
    ) -> bool {
        let Some(terminal) = self.terminal else {
            return false;
        };
        floor.kind() == terminal.kind()
            && floor.operation() == *operation.as_bytes()
            && floor.sandbox() == *self.sandbox.as_bytes()
            && floor.project() == self.project
            && floor.source_commitment() == self.source_commitment
            && floor.issue() == self.reservation.issue()
            && floor.reservation_digest() == self.reservation.record_digest()
            && floor.client_nonce() == self.reservation.client_nonce()
            && floor.names() == self.reservation.names()
            && floor.challenge_digest()
                == self
                    .challenge
                    .map(|row| row.record_digest())
                    .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            && floor.root_terminal_digest() == terminal.record_digest()
            && self
                .acceptance_digest()
                .is_ok_and(|digest| digest == floor.controller_acceptance_digest())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProjectAdmissionMetadataDataErrorV1> {
        self.validate()?;
        let body_end = FIXED_BODY_BYTES + self.original_projection.len();
        let mut bytes = vec![0; body_end + 32];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = self.phase as u8;
        bytes[12..16].copy_from_slice(
            &u32::try_from(self.original_projection.len())
                .map_err(|_| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)?
                .to_be_bytes(),
        );
        bytes[16..48].copy_from_slice(self.admission_revision.as_bytes());
        bytes[48..56].copy_from_slice(&self.admission_generation.to_be_bytes());
        bytes[56..88].copy_from_slice(self.source_commitment.as_bytes());
        bytes[88..104].copy_from_slice(self.sandbox.as_bytes());
        bytes[104..120].copy_from_slice(self.project.as_bytes());
        bytes[120..152].copy_from_slice(&self.capacity_id);
        bytes[152..288].copy_from_slice(&self.reservation.record_bytes());
        if let Some(challenge) = self.challenge {
            bytes[288..520].copy_from_slice(&challenge.record_bytes());
        }
        match self.terminal {
            None => {}
            Some(RetainedRootProjectTerminalV1::Outcome(outcome)) => {
                bytes[11] = 1;
                bytes[520..832].copy_from_slice(&outcome.record_bytes());
            }
            Some(RetainedRootProjectTerminalV1::Cancellation(marker)) => {
                bytes[11] = 2;
                bytes[520..632].copy_from_slice(&marker.record_bytes());
            }
        }
        bytes[832..992].copy_from_slice(&self.source_heads.record_bytes());
        if let Some(floor) = self.retired_floor {
            bytes[992..1024].copy_from_slice(floor.as_bytes());
        }
        bytes[FIXED_BODY_BYTES..body_end].copy_from_slice(&self.original_projection);
        let checksum = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes[..body_end])
            .finalize();
        bytes[body_end..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProjectAdmissionMetadataDataErrorV1> {
        if bytes.len() < FIXED_BODY_BYTES + 32
            || bytes.len() > MAXIMUM_RECORD_BYTES
            || bytes[..8] != MAGIC[..]
            || bytes[8..10] != 1_u16.to_be_bytes()
        {
            return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
        }
        let projection_length = u32::from_be_bytes(take(bytes, 12)?) as usize;
        if projection_length == 0
            || projection_length > MAXIMUM_RETAINED_PUBLIC_PROJECTION_BYTES
            || FIXED_BODY_BYTES
                .checked_add(projection_length)
                .and_then(|length| length.checked_add(32))
                != Some(bytes.len())
        {
            return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
        }
        let phase = match bytes[10] {
            1 => ProjectAdmissionPhaseV1::Prepared,
            2 => ProjectAdmissionPhaseV1::DispatchAuthorized,
            3 => ProjectAdmissionPhaseV1::AcceptedRootTerminal,
            4 => ProjectAdmissionPhaseV1::RootRetired,
            _ => return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata),
        };
        let terminal = match bytes[11] {
            0 if bytes[520..832] == [0; 312] => None,
            1 => Some(RetainedRootProjectTerminalV1::Outcome(
                RootProjectAdmissionOutcomeV1::from_record_bytes(&bytes[520..832])
                    .map_err(|_| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)?,
            )),
            2 if bytes[632..832] == [0; 200] => Some(RetainedRootProjectTerminalV1::Cancellation(
                RootProjectReservationCancellationV1::from_record_bytes(&bytes[520..632])
                    .map_err(|_| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)?,
            )),
            _ => return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata),
        };
        let row = Self {
            admission_revision: ObjectDigest::from_bytes(take(bytes, 16)?),
            admission_generation: u64::from_be_bytes(take(bytes, 48)?),
            source_commitment: ObjectDigest::from_bytes(take(bytes, 56)?),
            sandbox: SandboxId::from_bytes(take(bytes, 88)?),
            project: ProjectId::from_bytes(take(bytes, 104)?),
            capacity_id: take(bytes, 120)?,
            reservation: SourceProjectAdmissionReservationV1::from_record_bytes(&bytes[152..288])
                .map_err(|_| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)?,
            phase,
            challenge: if bytes[288..520] == [0; 232] {
                None
            } else {
                Some(
                    SourceProjectAdmissionChallengeV1::from_record_bytes(&bytes[288..520])
                        .map_err(|_| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)?,
                )
            },
            terminal,
            retired_floor: {
                let digest = take::<32>(bytes, 992)?;
                (digest != [0; 32]).then_some(ObjectDigest::from_bytes(digest))
            },
            source_heads: HistoricalCreateProjectSourceHeadsV1::from_record_bytes(&bytes[832..992])
                .ok_or_else(|| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)?,
            original_projection: bytes[FIXED_BODY_BYTES..bytes.len() - 32].to_vec(),
        };
        if row.encode()?.as_slice() != bytes {
            return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
        }
        Ok(row)
    }

    pub fn validate(&self) -> Result<(), ProjectAdmissionMetadataDataErrorV1> {
        if self.admission_revision.as_bytes() == &[0; 32]
            || self.admission_generation != 1
            || self.source_commitment.as_bytes() == &[0; 32]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.project.as_bytes() == &[0; 16]
            || self.project != self.reservation.project()
            || self.capacity_id == [0; 32]
            || self
                .retired_floor
                .is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || self.original_projection.is_empty()
            || self.original_projection.len() > MAXIMUM_RETAINED_PUBLIC_PROJECTION_BYTES
            || !self.source_heads.is_valid()
        {
            return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
        }
        let terminal_phase = matches!(
            self.phase,
            ProjectAdmissionPhaseV1::AcceptedRootTerminal | ProjectAdmissionPhaseV1::RootRetired
        );
        if terminal_phase != self.terminal.is_some()
            || (self.phase == ProjectAdmissionPhaseV1::RootRetired) != self.retired_floor.is_some()
            || (!terminal_phase && self.challenge.is_some())
        {
            return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
        }
        if let Some(challenge) = self.challenge
            && (challenge.issue() != self.reservation.issue()
                || challenge.project() != self.project
                || challenge.names() != self.reservation.names())
        {
            return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
        }
        match self.terminal {
            None => {}
            Some(RetainedRootProjectTerminalV1::Outcome(outcome)) => {
                let challenge = self.challenge.ok_or_else(|| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)?;
                if outcome.project() != self.project
                    || outcome.client_nonce() != self.reservation.client_nonce()
                    || outcome.stage() != challenge.stage()
                    || outcome.source_row() != challenge.record_digest()
                    || (outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed
                        && (challenge.kind()
                            != SourceProjectAdmissionChallengeKindV1::Admission
                            || outcome.sandbox() != *self.sandbox.as_bytes()
                            || outcome.source_commitment() != self.source_commitment))
                {
                    return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
                }
            }
            Some(RetainedRootProjectTerminalV1::Cancellation(marker)) => {
                if self.challenge.is_some()
                    || marker.project() != self.project
                    || marker.client_nonce() != self.reservation.client_nonce()
                    || marker.reservation() != self.reservation.record_digest()
                {
                    return Err(ProjectAdmissionMetadataDataErrorV1::InvalidMetadata);
                }
            }
        }
        Ok(())
    }
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProjectAdmissionMetadataDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)?
        .try_into()
        .map_err(|_| ProjectAdmissionMetadataDataErrorV1::InvalidMetadata)
}
