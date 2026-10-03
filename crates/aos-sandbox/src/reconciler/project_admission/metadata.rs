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

use crate::controller_service::public_projection::MAXIMUM_RETAINED_PUBLIC_PROJECTION_BYTES;
use crate::journal::{SourceProjectAdmissionChallengeV1, SourceProjectAdmissionReservationV1};
use crate::policy_compiler::{
    HistoricalCreateProjectSourceHeadsV1, RootProjectAdmissionOutcomeKindV1,
    RootProjectAdmissionOutcomeV1, RootProjectHistoryFloorV1, RootProjectHistoryTerminalKindV1,
    RootProjectReservationCancellationV1,
};

use super::{ReconcilerError, invalid_metadata};

const MAGIC: &[u8; 8] = b"AOSCPT01";
const DOMAIN: &[u8] = b"aos.sandbox.controller-project-terminal-metadata.v1\0";
const FIXED_BODY_BYTES: usize = 1024;
pub(in crate::reconciler) const MAXIMUM_RECORD_BYTES: usize =
    FIXED_BODY_BYTES + MAXIMUM_RETAINED_PUBLIC_PROJECTION_BYTES + 32;

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(in crate::reconciler) enum ProjectAdmissionPhase {
    Prepared = 1,
    DispatchAuthorized = 2,
    AcceptedRootTerminal = 3,
    RootRetired = 4,
}

/// Stores historical bytes, never a transport-authenticated terminal proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::reconciler) enum RetainedRootProjectTerminal {
    Outcome(RootProjectAdmissionOutcomeV1),
    Cancellation(RootProjectReservationCancellationV1),
}

impl RetainedRootProjectTerminal {
    pub(super) fn kind(self) -> RootProjectHistoryTerminalKindV1 {
        match self {
            Self::Outcome(row) if row.kind() == RootProjectAdmissionOutcomeKindV1::Committed => {
                RootProjectHistoryTerminalKindV1::Committed
            }
            Self::Outcome(_) => RootProjectHistoryTerminalKindV1::Aborted,
            Self::Cancellation(_) => RootProjectHistoryTerminalKindV1::CanceledReservation,
        }
    }

    pub(super) fn record_digest(self) -> ObjectDigest {
        match self {
            Self::Outcome(row) => row.record_digest(),
            Self::Cancellation(row) => row.record_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::reconciler) struct ProjectAdmissionMetadata {
    pub(in crate::reconciler) admission_revision: ObjectDigest,
    pub(in crate::reconciler) admission_generation: u64,
    pub(in crate::reconciler) source_commitment: ObjectDigest,
    pub(in crate::reconciler) sandbox: SandboxId,
    pub(in crate::reconciler) project: ProjectId,
    pub(in crate::reconciler) reservation: SourceProjectAdmissionReservationV1,
    pub(in crate::reconciler) capacity_id: [u8; 32],
    pub(in crate::reconciler) phase: ProjectAdmissionPhase,
    pub(in crate::reconciler) challenge: Option<SourceProjectAdmissionChallengeV1>,
    pub(in crate::reconciler) terminal: Option<RetainedRootProjectTerminal>,
    pub(in crate::reconciler) retired_floor: Option<ObjectDigest>,
    pub(in crate::reconciler) source_heads: HistoricalCreateProjectSourceHeadsV1,
    pub(in crate::reconciler) original_projection: Vec<u8>,
}

impl ProjectAdmissionMetadata {
    pub(crate) fn acceptance_digest(&self) -> Result<ObjectDigest, ReconcilerError> {
        if !matches!(
            self.phase,
            ProjectAdmissionPhase::AcceptedRootTerminal | ProjectAdmissionPhase::RootRetired
        ) {
            return Err(invalid_metadata());
        }
        let accepted = Self {
            phase: ProjectAdmissionPhase::AcceptedRootTerminal,
            retired_floor: None,
            ..self.clone()
        };
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(accepted.encode()?).into(),
        ))
    }

    pub(super) fn matches_floor(
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

    pub(in crate::reconciler) fn encode(&self) -> Result<Vec<u8>, ReconcilerError> {
        self.validate()?;
        let body_end = FIXED_BODY_BYTES + self.original_projection.len();
        let mut bytes = vec![0; body_end + 32];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = self.phase as u8;
        bytes[12..16].copy_from_slice(
            &u32::try_from(self.original_projection.len())
                .map_err(|_| invalid_metadata())?
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
            Some(RetainedRootProjectTerminal::Outcome(outcome)) => {
                bytes[11] = 1;
                bytes[520..832].copy_from_slice(&outcome.record_bytes());
            }
            Some(RetainedRootProjectTerminal::Cancellation(marker)) => {
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

    pub(in crate::reconciler) fn decode(bytes: &[u8]) -> Result<Self, ReconcilerError> {
        if bytes.len() < FIXED_BODY_BYTES + 32
            || bytes.len() > MAXIMUM_RECORD_BYTES
            || bytes[..8] != MAGIC[..]
            || bytes[8..10] != 1_u16.to_be_bytes()
        {
            return Err(invalid_metadata());
        }
        let projection_length = u32::from_be_bytes(take(bytes, 12)?) as usize;
        if projection_length == 0
            || projection_length > MAXIMUM_RETAINED_PUBLIC_PROJECTION_BYTES
            || FIXED_BODY_BYTES
                .checked_add(projection_length)
                .and_then(|length| length.checked_add(32))
                != Some(bytes.len())
        {
            return Err(invalid_metadata());
        }
        let phase = match bytes[10] {
            1 => ProjectAdmissionPhase::Prepared,
            2 => ProjectAdmissionPhase::DispatchAuthorized,
            3 => ProjectAdmissionPhase::AcceptedRootTerminal,
            4 => ProjectAdmissionPhase::RootRetired,
            _ => return Err(invalid_metadata()),
        };
        let terminal = match bytes[11] {
            0 if bytes[520..832] == [0; 312] => None,
            1 => Some(RetainedRootProjectTerminal::Outcome(
                RootProjectAdmissionOutcomeV1::from_record_bytes(&bytes[520..832])
                    .map_err(|_| invalid_metadata())?,
            )),
            2 if bytes[632..832] == [0; 200] => Some(RetainedRootProjectTerminal::Cancellation(
                RootProjectReservationCancellationV1::from_record_bytes(&bytes[520..632])
                    .map_err(|_| invalid_metadata())?,
            )),
            _ => return Err(invalid_metadata()),
        };
        let row = Self {
            admission_revision: ObjectDigest::from_bytes(take(bytes, 16)?),
            admission_generation: u64::from_be_bytes(take(bytes, 48)?),
            source_commitment: ObjectDigest::from_bytes(take(bytes, 56)?),
            sandbox: SandboxId::from_bytes(take(bytes, 88)?),
            project: ProjectId::from_bytes(take(bytes, 104)?),
            capacity_id: take(bytes, 120)?,
            reservation: SourceProjectAdmissionReservationV1::from_record_bytes(&bytes[152..288])
                .map_err(|_| invalid_metadata())?,
            phase,
            challenge: if bytes[288..520] == [0; 232] {
                None
            } else {
                Some(
                    SourceProjectAdmissionChallengeV1::from_record_bytes(&bytes[288..520])
                        .map_err(|_| invalid_metadata())?,
                )
            },
            terminal,
            retired_floor: {
                let digest = take::<32>(bytes, 992)?;
                (digest != [0; 32]).then_some(ObjectDigest::from_bytes(digest))
            },
            source_heads: HistoricalCreateProjectSourceHeadsV1::from_record_bytes(&bytes[832..992])
                .ok_or_else(invalid_metadata)?,
            original_projection: bytes[FIXED_BODY_BYTES..bytes.len() - 32].to_vec(),
        };
        if row.encode()?.as_slice() != bytes {
            return Err(invalid_metadata());
        }
        Ok(row)
    }

    pub(super) fn validate(&self) -> Result<(), ReconcilerError> {
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
            return Err(invalid_metadata());
        }
        let terminal_phase = matches!(
            self.phase,
            ProjectAdmissionPhase::AcceptedRootTerminal | ProjectAdmissionPhase::RootRetired
        );
        if terminal_phase != self.terminal.is_some()
            || (self.phase == ProjectAdmissionPhase::RootRetired) != self.retired_floor.is_some()
            || (!terminal_phase && self.challenge.is_some())
        {
            return Err(invalid_metadata());
        }
        if let Some(challenge) = self.challenge
            && (challenge.issue() != self.reservation.issue()
                || challenge.project() != self.project
                || challenge.names() != self.reservation.names())
        {
            return Err(invalid_metadata());
        }
        match self.terminal {
            None => {}
            Some(RetainedRootProjectTerminal::Outcome(outcome)) => {
                let challenge = self.challenge.ok_or_else(invalid_metadata)?;
                if outcome.project() != self.project
                    || outcome.client_nonce() != self.reservation.client_nonce()
                    || outcome.stage() != challenge.stage()
                    || outcome.source_row() != challenge.record_digest()
                    || (outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed
                        && (challenge.kind()
                            != crate::journal::SourceProjectAdmissionChallengeKindV1::Admission
                            || outcome.sandbox() != *self.sandbox.as_bytes()
                            || outcome.source_commitment() != self.source_commitment))
                {
                    return Err(invalid_metadata());
                }
            }
            Some(RetainedRootProjectTerminal::Cancellation(marker)) => {
                if self.challenge.is_some()
                    || marker.project() != self.project
                    || marker.client_nonce() != self.reservation.client_nonce()
                    || marker.reservation() != self.reservation.record_digest()
                {
                    return Err(invalid_metadata());
                }
            }
        }
        Ok(())
    }
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ReconcilerError> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(invalid_metadata)?
        .try_into()
        .map_err(|_| invalid_metadata())
}
