//! Durable Source-writer challenge for pre-Q04 project-policy admission.
//!
//! This row records a Root nonce under the retained Source writer before the
//! independent Source signer reads the same ancestry and physical names. It
//! does not create a Q04 hold or authorize a project source at Root.
//! Settlement retains the mutation fence until an exact Root history-floor
//! ACK is joined to Controller's still-held retirement acceptance. Reservation
//! version 2 deliberately rejects the undeployed version-1 history: prior
//! issue advancement did not prove this ACK fence.
//!
//! ```text
//! AOSQPA01 | version:u16=2 | kind:u8 | reserved[5]=0 | issue:u64 |
//! Root-nonce:16 | Root-cut:32 | project:16 | ancestry-head:32 |
//! Root-stage-digest:32 |
//! directory/journal/lock (device:u64, inode:u64 each) |
//! SHA-256(Source-project-challenge-domain || preceding 200 bytes):32
//! ```
//!
//! ```text
//! AOSQPT01 | version:u16=1 | reserved[6]=0 | issue:u64 |
//! SHA(actual-reservation):32 | SHA(actual-unpadded-Source-terminal):32 |
//! Root-history-floor-digest:32 | domain-separated-checksum:32
//! ```

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{
    Journal, JournalError, JournalRecord, JournalTransaction, ProtectedJournalNamesV1,
    RecordNamespace, source_domain_policy_hold,
};
use crate::policy_compiler::{
    RootProjectAdmissionOutcomeProofV1, RootProjectHistoryFloorProofV1,
    RootProjectReservationCancellationProofV1,
};
use crate::reconciler::ControllerProjectHistoryAcceptanceV1;

const KEY: &[u8] = b"\0aos-source-project-admission-challenge-v1\0";
const MAGIC: &[u8; 8] = b"AOSQPA01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission-challenge.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission-transaction.v1\0";
const RECORD_BYTES: usize = 232;
const RESERVATION_KEY: &[u8] = b"\0aos-source-project-admission-reservation-v1\0";
const RESERVATION_MAGIC: &[u8; 8] = b"AOSQPV01";
const RESERVATION_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission-reservation.v1\0";
const RESERVATION_BYTES: usize = 136;
const CANCELLATION_KEY: &[u8] = b"\0aos-source-project-reservation-cancellation-v1\0";
const CANCELLATION_MAGIC: &[u8; 8] = b"AOSQPC02";
const CANCELLATION_DOMAIN: &[u8] = b"aos.sandbox.source-project-reservation-cancellation.v1\0";
const CANCELLATION_BYTES: usize = 120;
const RETIREMENT_ACK_KEY: &[u8] = b"\0aos-source-project-terminal-retirement-ack-v1\0";
const RETIREMENT_ACK_MAGIC: &[u8; 8] = b"AOSQPT01";
const RETIREMENT_ACK_DOMAIN: &[u8] = b"aos.sandbox.source-project-terminal-retirement-ack.v1\0";
const RETIREMENT_ACK_BYTES: usize = 152;

/// Distinguishes ancestry-bearing admission from a nonauthorizing abort row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceProjectAdmissionChallengeKindV1 {
    /// The current typed Source ancestry can be used for Root admission.
    Admission,
    /// Only the durable Source challenge and physical names can be retired.
    AbortOnly,
}
const SETTLEMENT_KEY: &[u8] = b"\0aos-source-project-admission-settlement-v1\0";
const SETTLEMENT_MAGIC: &[u8; 8] = b"AOSQPC01";
const SETTLEMENT_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission-settlement.v1\0";
const SETTLEMENT_BYTES: usize = 152;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceProjectAdmissionTransition {
    None,
    Reserve,
    Acquire,
    Settle,
    CancelReservation,
    AcknowledgeRetirement,
}

/// Bounds a canonical Source settlement, or a zero-padded cancellation.
pub const SOURCE_PROJECT_ADMISSION_TERMINAL_BYTES_V1: usize = SETTLEMENT_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceProjectTerminalRetirementAckV1 {
    issue: u64,
    reservation: ObjectDigest,
    source_terminal: ObjectDigest,
    root_floor: ObjectDigest,
}

impl SourceProjectTerminalRetirementAckV1 {
    fn encode(self) -> [u8; RETIREMENT_ACK_BYTES] {
        let mut bytes = [0; RETIREMENT_ACK_BYTES];
        bytes[..8].copy_from_slice(RETIREMENT_ACK_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.issue.to_be_bytes());
        bytes[24..56].copy_from_slice(self.reservation.as_bytes());
        bytes[56..88].copy_from_slice(self.source_terminal.as_bytes());
        bytes[88..120].copy_from_slice(self.root_floor.as_bytes());
        let checksum = Sha256::new()
            .chain_update(RETIREMENT_ACK_DOMAIN)
            .chain_update(&bytes[..120])
            .finalize();
        bytes[120..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RETIREMENT_ACK_BYTES
            || bytes.get(..8) != Some(RETIREMENT_ACK_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let row = Self {
            issue: u64::from_be_bytes(take::<8>(bytes, 16)?),
            reservation: ObjectDigest::from_bytes(take::<32>(bytes, 24)?),
            source_terminal: ObjectDigest::from_bytes(take::<32>(bytes, 56)?),
            root_floor: ObjectDigest::from_bytes(take::<32>(bytes, 88)?),
        };
        if row.issue == 0
            || [row.reservation, row.source_terminal, row.root_floor]
                .iter()
                .any(|digest| digest.as_bytes() == &[0; 32])
            || row.encode().as_slice() != bytes
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceProjectTerminalRecordV1 {
    Settlement(SourceProjectAdmissionSettlementV1),
    Cancellation(SourceProjectReservationCancellationV1),
}

/// Retains actual canonical Source rows for a completed-terminal readback.
///
/// This structural projection grants no Root authority. Only independent
/// Source signature verification authenticates a transported observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceProjectAdmissionTerminalV1 {
    reservation: SourceProjectAdmissionReservationV1,
    challenge: Option<SourceProjectAdmissionChallengeV1>,
    terminal: SourceProjectTerminalRecordV1,
}

impl SourceProjectAdmissionTerminalV1 {
    /// Returns the actual retained pre-stage reservation.
    pub const fn reservation(self) -> SourceProjectAdmissionReservationV1 {
        self.reservation
    }

    /// Returns the actual challenged row, absent for reservation cancellation.
    pub const fn challenge(self) -> Option<SourceProjectAdmissionChallengeV1> {
        self.challenge
    }

    /// Returns SHA-256 of the unpadded actual Source terminal record.
    pub fn source_terminal_digest(self) -> ObjectDigest {
        let bytes = self.record_bytes();
        let length = match self.terminal {
            SourceProjectTerminalRecordV1::Settlement(_) => SETTLEMENT_BYTES,
            SourceProjectTerminalRecordV1::Cancellation(_) => CANCELLATION_BYTES,
        };
        ObjectDigest::from_bytes(Sha256::digest(&bytes[..length]).into())
    }

    /// Returns the exact Root outcome or cancellation marker digest.
    pub const fn root_terminal_digest(self) -> ObjectDigest {
        match self.terminal {
            SourceProjectTerminalRecordV1::Settlement(row) => row.outcome,
            SourceProjectTerminalRecordV1::Cancellation(row) => row.root_marker,
        }
    }

    /// Returns the actual Source terminal, padding only a cancellation's tail.
    pub fn record_bytes(self) -> [u8; SOURCE_PROJECT_ADMISSION_TERMINAL_BYTES_V1] {
        match self.terminal {
            SourceProjectTerminalRecordV1::Settlement(row) => row.encode(),
            SourceProjectTerminalRecordV1::Cancellation(row) => {
                let mut bytes = [0; SOURCE_PROJECT_ADMISSION_TERMINAL_BYTES_V1];
                bytes[..CANCELLATION_BYTES].copy_from_slice(&row.encode());
                bytes
            }
        }
    }

    pub(crate) fn from_record_parts(
        reservation: SourceProjectAdmissionReservationV1,
        challenge: Option<SourceProjectAdmissionChallengeV1>,
        bytes: &[u8],
    ) -> Result<Self, JournalError> {
        let terminal = if bytes.get(..8) == Some(SETTLEMENT_MAGIC.as_slice()) {
            SourceProjectTerminalRecordV1::Settlement(SourceProjectAdmissionSettlementV1::decode(
                bytes,
            )?)
        } else if bytes.len() == SOURCE_PROJECT_ADMISSION_TERMINAL_BYTES_V1
            && bytes[CANCELLATION_BYTES..] == [0; SETTLEMENT_BYTES - CANCELLATION_BYTES]
        {
            SourceProjectTerminalRecordV1::Cancellation(
                SourceProjectReservationCancellationV1::decode(&bytes[..CANCELLATION_BYTES])?,
            )
        } else {
            return Err(JournalError::ProtectedBoundary);
        };
        let rows = CurrentProjectAdmissionRows {
            reservation: Some(reservation),
            challenge,
            settlement: match terminal {
                SourceProjectTerminalRecordV1::Settlement(row) => Some(row),
                _ => None,
            },
            cancellation: match terminal {
                SourceProjectTerminalRecordV1::Cancellation(row) => Some(row),
                _ => None,
            },
            retirement_ack: None,
        };
        rows.require_joined()?;
        rows.terminal().ok_or(JournalError::ProtectedBoundary)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceProjectReservationCancellationV1 {
    issue: u64,
    reservation: ObjectDigest,
    root_marker: ObjectDigest,
}

impl SourceProjectReservationCancellationV1 {
    fn encode(self) -> [u8; CANCELLATION_BYTES] {
        let mut bytes = [0; CANCELLATION_BYTES];
        bytes[..8].copy_from_slice(CANCELLATION_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.issue.to_be_bytes());
        bytes[24..56].copy_from_slice(self.reservation.as_bytes());
        bytes[56..88].copy_from_slice(self.root_marker.as_bytes());
        let checksum = Sha256::new()
            .chain_update(CANCELLATION_DOMAIN)
            .chain_update(&bytes[..88])
            .finalize();
        bytes[88..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != CANCELLATION_BYTES
            || bytes.get(..8) != Some(CANCELLATION_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let row = Self {
            issue: u64::from_be_bytes(take::<8>(bytes, 16)?),
            reservation: ObjectDigest::from_bytes(take::<32>(bytes, 24)?),
            root_marker: ObjectDigest::from_bytes(take::<32>(bytes, 56)?),
        };
        if row.issue == 0
            || row.reservation.as_bytes() == &[0; 32]
            || row.root_marker.as_bytes() == &[0; 32]
            || row.encode().as_slice() != bytes
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceProjectAdmissionSettlementV1 {
    issue: u64,
    challenge: ObjectDigest,
    stage: ObjectDigest,
    outcome: ObjectDigest,
}

impl SourceProjectAdmissionSettlementV1 {
    fn encode(self) -> [u8; SETTLEMENT_BYTES] {
        let mut bytes = [0; SETTLEMENT_BYTES];
        bytes[..8].copy_from_slice(SETTLEMENT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.issue.to_be_bytes());
        bytes[24..56].copy_from_slice(self.challenge.as_bytes());
        bytes[56..88].copy_from_slice(self.stage.as_bytes());
        bytes[88..120].copy_from_slice(self.outcome.as_bytes());
        let checksum = Sha256::new()
            .chain_update(SETTLEMENT_DOMAIN)
            .chain_update(&bytes[..120])
            .finalize();
        bytes[120..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != SETTLEMENT_BYTES
            || bytes.get(..8) != Some(SETTLEMENT_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let row = Self {
            issue: u64::from_be_bytes(take::<8>(bytes, 16)?),
            challenge: ObjectDigest::from_bytes(take::<32>(bytes, 24)?),
            stage: ObjectDigest::from_bytes(take::<32>(bytes, 56)?),
            outcome: ObjectDigest::from_bytes(take::<32>(bytes, 88)?),
        };
        if row.issue == 0
            || row.challenge.as_bytes() == &[0; 32]
            || row.stage.as_bytes() == &[0; 32]
            || row.outcome.as_bytes() == &[0; 32]
            || row.encode().as_slice() != bytes
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }

    fn matches(self, challenge: SourceProjectAdmissionChallengeV1) -> bool {
        self.issue == challenge.issue && self.challenge == challenge.record_digest()
    }
}

/// Bounds the canonical Source project-admission challenge row.
pub const SOURCE_PROJECT_ADMISSION_CHALLENGE_BYTES_V1: usize = RECORD_BYTES;

/// Bounds the canonical pre-stage Source reservation row.
pub const SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1: usize = RESERVATION_BYTES;

/// Retains Source journal headroom before Root may create a project stage.
///
/// The reservation does not assert ancestry or authorize Root admission. Its
/// immutable row is retained through the later Source challenge and outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceProjectAdmissionReservationV1 {
    issue: u64,
    client_nonce: [u8; 16],
    project: ProjectId,
    names: ProtectedJournalNamesV1,
}

impl SourceProjectAdmissionReservationV1 {
    /// Returns the monotone Source admission issue.
    pub const fn issue(self) -> u64 {
        self.issue
    }

    /// Returns the effect-owned nonce to be spent by one Root stage.
    pub const fn client_nonce(self) -> [u8; 16] {
        self.client_nonce
    }

    /// Returns the project named by the accepted Create.
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the fixed protected Source names.
    pub const fn names(self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the digest of the exact durable reservation row.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.encode()).into())
    }

    /// Returns the canonical row for a Source-only signed readback.
    #[must_use]
    pub fn record_bytes(self) -> [u8; RESERVATION_BYTES] {
        self.encode()
    }

    /// Decodes untrusted bytes without authenticating Source custody.
    ///
    /// # Errors
    ///
    /// Rejects changed fields, framing, or checksum.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, JournalError> {
        Self::decode(bytes)
    }

    fn encode(self) -> [u8; RESERVATION_BYTES] {
        let mut bytes = [0; RESERVATION_BYTES];
        bytes[..8].copy_from_slice(RESERVATION_MAGIC);
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.issue.to_be_bytes());
        bytes[24..40].copy_from_slice(&self.client_nonce);
        bytes[40..56].copy_from_slice(self.project.as_bytes());
        bytes[56..104].copy_from_slice(&self.names.to_bytes());
        let checksum = Sha256::new()
            .chain_update(RESERVATION_DOMAIN)
            .chain_update(&bytes[..104])
            .finalize();
        bytes[104..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RESERVATION_BYTES
            || bytes.get(..8) != Some(RESERVATION_MAGIC.as_slice())
            || bytes.get(8..10) != Some(2_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let row = Self {
            issue: u64::from_be_bytes(take::<8>(bytes, 16)?),
            client_nonce: take::<16>(bytes, 24)?,
            project: ProjectId::from_bytes(take::<16>(bytes, 40)?),
            names: ProtectedJournalNamesV1::from_bytes(&bytes[56..104])?,
        };
        if row.issue == 0
            || row.client_nonce == [0; 16]
            || row.project.as_bytes() == &[0; 16]
            || row.encode().as_slice() != bytes
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }
}

/// Retains one Root project-admission challenge spent under the Source writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceProjectAdmissionChallengeV1 {
    kind: SourceProjectAdmissionChallengeKindV1,
    issue: u64,
    nonce: [u8; 16],
    cut: ObjectDigest,
    project: ProjectId,
    ancestry: ObjectDigest,
    stage: ObjectDigest,
    names: ProtectedJournalNamesV1,
}

impl SourceProjectAdmissionChallengeV1 {
    /// Returns whether this row can support admission or only exact abort.
    pub const fn kind(self) -> SourceProjectAdmissionChallengeKindV1 {
        self.kind
    }
    /// Returns the monotone Source-journal challenge issue.
    pub const fn issue(self) -> u64 {
        self.issue
    }

    /// Returns the Root nonce spent under Source custody.
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the Root session cut.
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }

    /// Returns the challenged project.
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the protected Source ancestry head.
    pub const fn ancestry(self) -> ObjectDigest {
        self.ancestry
    }

    /// Returns the exact immutable Root stage for cold outcome recovery.
    pub const fn stage(self) -> ObjectDigest {
        self.stage
    }

    /// Returns the exact Source directory, journal, and lock identities.
    pub const fn names(self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the digest of the canonical durable row.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.encode()).into())
    }

    /// Returns the exact canonical row for transport to Root.
    #[must_use]
    pub fn record_bytes(self) -> [u8; RECORD_BYTES] {
        self.encode()
    }

    /// Decodes an untrusted row without granting Source writer authority.
    ///
    /// # Errors
    ///
    /// Rejects changed framing, fields, or checksum.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, JournalError> {
        Self::decode(bytes)
    }

    /// Checks this row against a retained writer or independent signer view.
    pub(crate) fn matches_current(
        self,
        nonce: [u8; 16],
        cut: ObjectDigest,
        project: ProjectId,
        ancestry: ObjectDigest,
        stage: ObjectDigest,
        names: ProtectedJournalNamesV1,
    ) -> bool {
        self.kind == SourceProjectAdmissionChallengeKindV1::Admission
            && self.nonce == nonce
            && self.cut == cut
            && self.project == project
            && self.ancestry == ancestry
            && self.stage == stage
            && self.names == names
    }

    fn encode(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        bytes[10] = match self.kind {
            SourceProjectAdmissionChallengeKindV1::Admission => 1,
            SourceProjectAdmissionChallengeKindV1::AbortOnly => 2,
        };
        bytes[16..24].copy_from_slice(&self.issue.to_be_bytes());
        bytes[24..40].copy_from_slice(&self.nonce);
        bytes[40..72].copy_from_slice(self.cut.as_bytes());
        bytes[72..88].copy_from_slice(self.project.as_bytes());
        bytes[88..120].copy_from_slice(self.ancestry.as_bytes());
        bytes[120..152].copy_from_slice(self.stage.as_bytes());
        bytes[152..200].copy_from_slice(&self.names.to_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..200])
            .finalize();
        bytes[200..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(2_u16.to_be_bytes().as_slice())
            || bytes[11..16] != [0; 5]
            || bytes[200..]
                != Sha256::new()
                    .chain_update(CHECKSUM_DOMAIN)
                    .chain_update(&bytes[..200])
                    .finalize()[..]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let row = Self {
            kind: match bytes[10] {
                1 => SourceProjectAdmissionChallengeKindV1::Admission,
                2 => SourceProjectAdmissionChallengeKindV1::AbortOnly,
                _ => return Err(JournalError::ProtectedBoundary),
            },
            issue: u64::from_be_bytes(take::<8>(bytes, 16)?),
            nonce: take::<16>(bytes, 24)?,
            cut: ObjectDigest::from_bytes(take::<32>(bytes, 40)?),
            project: ProjectId::from_bytes(take::<16>(bytes, 72)?),
            ancestry: ObjectDigest::from_bytes(take::<32>(bytes, 88)?),
            stage: ObjectDigest::from_bytes(take::<32>(bytes, 120)?),
            names: ProtectedJournalNamesV1::from_bytes(&bytes[152..200])?,
        };
        if row.issue == 0
            || row.nonce == [0; 16]
            || row.cut.as_bytes() == &[0; 32]
            || row.project.as_bytes() == &[0; 16]
            || (row.kind == SourceProjectAdmissionChallengeKindV1::Admission
                && row.ancestry.as_bytes() == &[0; 32])
            || (row.kind == SourceProjectAdmissionChallengeKindV1::AbortOnly
                && row.ancestry.as_bytes() != &[0; 32])
            || row.stage.as_bytes() == &[0; 32]
            || row.encode().as_slice() != bytes
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], JournalError> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

/// Replays only the typed row; callers establish protected custody first.
pub(crate) fn replay_source_project_admission_challenge_v1(
    journal: &Journal,
) -> Result<Option<SourceProjectAdmissionChallengeV1>, JournalError> {
    journal
        .get(RecordNamespace::DesiredState, KEY)
        .map(SourceProjectAdmissionChallengeV1::decode)
        .transpose()
}

fn current_reservation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<SourceProjectAdmissionReservationV1>, JournalError> {
    state
        .get(&(RecordNamespace::DesiredState, RESERVATION_KEY.to_vec()))
        .map(|bytes| SourceProjectAdmissionReservationV1::decode(bytes))
        .transpose()
}

fn current_cancellation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<SourceProjectReservationCancellationV1>, JournalError> {
    state
        .get(&(RecordNamespace::DesiredState, CANCELLATION_KEY.to_vec()))
        .map(|bytes| SourceProjectReservationCancellationV1::decode(bytes))
        .transpose()
}

#[derive(Clone, Copy)]
struct CurrentProjectAdmissionRows {
    reservation: Option<SourceProjectAdmissionReservationV1>,
    cancellation: Option<SourceProjectReservationCancellationV1>,
    challenge: Option<SourceProjectAdmissionChallengeV1>,
    settlement: Option<SourceProjectAdmissionSettlementV1>,
    retirement_ack: Option<SourceProjectTerminalRetirementAckV1>,
}

impl CurrentProjectAdmissionRows {
    fn terminal(self) -> Option<SourceProjectAdmissionTerminalV1> {
        let terminal = match (self.settlement, self.cancellation) {
            (Some(row), None) => SourceProjectTerminalRecordV1::Settlement(row),
            (None, Some(row)) => SourceProjectTerminalRecordV1::Cancellation(row),
            _ => return None,
        };
        Some(SourceProjectAdmissionTerminalV1 {
            reservation: self.reservation?,
            challenge: self.challenge,
            terminal,
        })
    }

    fn require_joined(self) -> Result<(), JournalError> {
        if self.challenge.is_some_and(|row| {
            !self.reservation.is_some_and(|reserved| {
                row.issue == reserved.issue
                    && row.project == reserved.project
                    && row.names == reserved.names
            })
        }) || self.settlement.is_some_and(|row| {
            !self
                .challenge
                .is_some_and(|challenge| row.matches(challenge) && row.stage == challenge.stage())
        }) || self.cancellation.is_some_and(|row| {
            self.challenge.is_some()
                || self.settlement.is_some()
                || !self.reservation.is_some_and(|reservation| {
                    row.issue == reservation.issue && row.reservation == reservation.record_digest()
                })
        }) || self.retirement_ack.is_some_and(|row| {
            !self.terminal().is_some_and(|terminal| {
                row.issue == terminal.reservation.issue()
                    && row.reservation == terminal.reservation.record_digest()
                    && row.source_terminal == terminal.source_terminal_digest()
            })
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

fn current_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<CurrentProjectAdmissionRows, JournalError> {
    let challenge = state
        .get(&(RecordNamespace::DesiredState, KEY.to_vec()))
        .map(|bytes| SourceProjectAdmissionChallengeV1::decode(bytes))
        .transpose()?;
    let settlement = state
        .get(&(RecordNamespace::DesiredState, SETTLEMENT_KEY.to_vec()))
        .map(|bytes| SourceProjectAdmissionSettlementV1::decode(bytes))
        .transpose()?;
    let reservation = current_reservation(state)?;
    let cancellation = current_cancellation(state)?;
    let retirement_ack = state
        .get(&(RecordNamespace::DesiredState, RETIREMENT_ACK_KEY.to_vec()))
        .map(|bytes| SourceProjectTerminalRetirementAckV1::decode(bytes))
        .transpose()?;
    let rows = CurrentProjectAdmissionRows {
        reservation,
        cancellation,
        challenge,
        settlement,
        retirement_ack,
    };
    rows.require_joined()?;
    Ok(rows)
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceProjectAdmissionTransition,
) -> Result<(), JournalError> {
    let CurrentProjectAdmissionRows {
        reservation,
        cancellation,
        challenge,
        settlement,
        retirement_ack,
    } = current_rows(state)?;
    let records = transaction.records();
    match transition {
        SourceProjectAdmissionTransition::None => {
            if reservation.is_some() && retirement_ack.is_none() {
                return Err(JournalError::ProtectedBoundary);
            }
            if records.iter().any(|record| {
                record.namespace() == RecordNamespace::DesiredState
                    && (record.key() == KEY
                        || record.key() == SETTLEMENT_KEY
                        || record.key() == RESERVATION_KEY
                        || record.key() == CANCELLATION_KEY
                        || record.key() == RETIREMENT_ACK_KEY)
            }) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        SourceProjectAdmissionTransition::Reserve => {
            let [record, rest @ ..] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != RESERVATION_KEY
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let next = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(SourceProjectAdmissionReservationV1::decode)?;
            match (reservation, challenge, settlement, rest) {
                (None, None, None, []) if next.issue == 1 && retirement_ack.is_none() => {}
                (
                    Some(previous),
                    Some(_),
                    Some(_),
                    [delete_challenge, delete_settlement, delete_ack],
                ) if retirement_ack.is_some()
                    && next.issue
                        == previous
                            .issue
                            .checked_add(1)
                            .ok_or(JournalError::ProtectedBoundary)?
                    && delete_challenge.namespace() == RecordNamespace::DesiredState
                    && delete_challenge.key() == KEY
                    && delete_challenge.value().is_none()
                    && delete_settlement.namespace() == RecordNamespace::DesiredState
                    && delete_settlement.key() == SETTLEMENT_KEY
                    && delete_settlement.value().is_none()
                    && is_ack_delete(delete_ack) => {}
                (Some(previous), None, None, [delete_cancellation, delete_ack])
                    if cancellation.is_some()
                        && retirement_ack.is_some()
                        && next.issue
                            == previous
                                .issue
                                .checked_add(1)
                                .ok_or(JournalError::ProtectedBoundary)?
                        && delete_cancellation.namespace() == RecordNamespace::DesiredState
                        && delete_cancellation.key() == CANCELLATION_KEY
                        && delete_cancellation.value().is_none()
                        && is_ack_delete(delete_ack) => {}
                _ => return Err(JournalError::ProtectedBoundary),
            }
        }
        SourceProjectAdmissionTransition::Acquire => {
            let [record, rest @ ..] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            if record.namespace() != RecordNamespace::DesiredState || record.key() != KEY {
                return Err(JournalError::ProtectedBoundary);
            }
            let next = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(SourceProjectAdmissionChallengeV1::decode)?;
            if !rest.is_empty()
                || challenge.is_some()
                || settlement.is_some()
                || cancellation.is_some()
                || retirement_ack.is_some()
                || !reservation.is_some_and(|reserved| {
                    next.issue == reserved.issue
                        && next.project == reserved.project
                        && next.names == reserved.names
                })
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        SourceProjectAdmissionTransition::Settle => {
            let [record] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            let row = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(SourceProjectAdmissionSettlementV1::decode)?;
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != SETTLEMENT_KEY
                || settlement.is_some()
                || cancellation.is_some()
                || retirement_ack.is_some()
                || !challenge.is_some_and(|challenge| row.matches(challenge))
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        SourceProjectAdmissionTransition::CancelReservation => {
            let [record] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            let row = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(SourceProjectReservationCancellationV1::decode)?;
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != CANCELLATION_KEY
                || challenge.is_some()
                || settlement.is_some()
                || cancellation.is_some()
                || retirement_ack.is_some()
                || !reservation.is_some_and(|reservation| {
                    row.issue == reservation.issue && row.reservation == reservation.record_digest()
                })
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        SourceProjectAdmissionTransition::AcknowledgeRetirement => {
            let [record] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            let row = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(SourceProjectTerminalRetirementAckV1::decode)?;
            let rows = current_rows(state)?;
            let terminal = rows.terminal().ok_or(JournalError::ProtectedBoundary)?;
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != RETIREMENT_ACK_KEY
                || retirement_ack.is_some()
                || row.issue != terminal.reservation.issue()
                || row.reservation != terminal.reservation.record_digest()
                || row.source_terminal != terminal.source_terminal_digest()
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    let rows = current_rows(state)?;
    if rows.reservation.is_some() && rows.retirement_ack.is_none() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn is_ack_delete(record: &JournalRecord) -> bool {
    record.namespace() == RecordNamespace::DesiredState
        && record.key() == RETIREMENT_ACK_KEY
        && record.value().is_none()
}

impl Journal {
    /// Replays the actual completed Source rows without renewing their authority.
    ///
    /// # Errors
    ///
    /// Rejects a poisoned journal, malformed row, or mixed terminal/ACK join.
    pub(crate) fn source_project_admission_terminal_v1(
        &self,
    ) -> Result<Option<SourceProjectAdmissionTerminalV1>, JournalError> {
        self.ensure_healthy()?;
        Ok(current_rows(&self.state)?.terminal())
    }

    /// Lifts only the exact terminal fence after Root and held Controller ACK.
    ///
    /// The borrowed Controller acceptance rechecks its still-held journal;
    /// a detached Root proof or a Source settlement alone cannot lift custody.
    ///
    /// # Errors
    ///
    /// Rejects changed Source names, foreign Root/Controller evidence, conflicting
    /// replay, or failed durable commit and exact protected readback.
    pub(crate) fn acknowledge_source_project_terminal_retirement_v1(
        &mut self,
        proof: RootProjectHistoryFloorProofV1,
        controller: &ControllerProjectHistoryAcceptanceV1<'_>,
    ) -> Result<(), JournalError> {
        source_domain_policy_hold::ensure_source_domain(self)?;
        let rows = current_rows(&self.state)?;
        let terminal = rows.terminal().ok_or(JournalError::ProtectedBoundary)?;
        let floor = proof.floor();
        if self.protected_writer_physical_names_v1()? != terminal.reservation.names() {
            return Err(JournalError::ProtectedBoundary);
        }
        controller.validate_source_ack(
            floor,
            terminal.reservation(),
            terminal.challenge(),
            terminal.source_terminal_digest(),
        )?;
        let ack = SourceProjectTerminalRetirementAckV1 {
            issue: terminal.reservation.issue(),
            reservation: terminal.reservation.record_digest(),
            source_terminal: terminal.source_terminal_digest(),
            root_floor: floor.record_digest(),
        };
        if let Some(prior) = rows.retirement_ack {
            return if prior == ack {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            };
        }
        self.commit_source_project_admission_transition(
            &single_record_transaction(RETIREMENT_ACK_KEY, &ack.encode())?,
            SourceProjectAdmissionTransition::AcknowledgeRetirement,
        )?;
        controller.validate_source_ack(
            floor,
            terminal.reservation(),
            terminal.challenge(),
            terminal.source_terminal_digest(),
        )?;
        let current = current_rows(&self.state)?;
        if current.retirement_ack != Some(ack)
            || current.terminal() != Some(terminal)
            || self.protected_writer_physical_names_v1()? != terminal.reservation.names()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Replays the reservation and whether Root has durably canceled it.
    ///
    /// A `false` flag does not mean this issue is pending: a settled challenge
    /// deliberately retains its reservation until the next issue replaces it.
    pub(crate) fn source_project_admission_reservation_status_v1(
        &self,
    ) -> Result<Option<(SourceProjectAdmissionReservationV1, bool)>, JournalError> {
        let rows = current_rows(&self.state)?;
        Ok(rows
            .reservation
            .map(|row| (row, rows.cancellation.is_some())))
    }

    /// Replays the immutable Source reservation before or after promotion.
    pub(crate) fn source_project_admission_reservation_v1(
        &self,
    ) -> Result<Option<SourceProjectAdmissionReservationV1>, JournalError> {
        Ok(current_rows(&self.state)?.reservation)
    }

    /// Retires an unconsumed reservation only after exact Root cancellation.
    ///
    /// The opaque proof comes solely from a peer-checked fixed Root socket
    /// query; an absent stage or failed RPC alone cannot lift this fence.
    pub(crate) fn settle_source_project_admission_reservation_v1(
        &mut self,
        expected: SourceProjectAdmissionReservationV1,
        proof: RootProjectReservationCancellationProofV1,
    ) -> Result<(), JournalError> {
        source_domain_policy_hold::ensure_source_domain(self)?;
        let marker = proof.marker();
        let rows = current_rows(&self.state)?;
        if rows.reservation != Some(expected)
            || self.protected_writer_physical_names_v1()? != expected.names()
            || marker.reservation() != expected.record_digest()
            || marker.client_nonce() != expected.client_nonce()
            || marker.project() != expected.project()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let cancellation = SourceProjectReservationCancellationV1 {
            issue: expected.issue(),
            reservation: expected.record_digest(),
            root_marker: marker.record_digest(),
        };
        let prior = rows.cancellation;
        if let Some(prior) = prior {
            return if prior == cancellation {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            };
        }
        if rows.challenge.is_some() || rows.settlement.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let transaction = cancellation_transaction(cancellation)?;
        self.commit_source_project_admission_transition(
            &transaction,
            SourceProjectAdmissionTransition::CancelReservation,
        )?;
        if current_cancellation(&self.state)? != Some(cancellation)
            || self.protected_writer_physical_names_v1()? != expected.names()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Selects the exact next reservation while the Source writer is retained.
    ///
    /// Root may reserve its own cancellation headroom for this canonical row
    /// before Source appends it. This preview grants no Source authority and
    /// must be rechecked by the later commit under the same writer.
    /// Identical pending replay retains the issue; an ACKed terminal instead
    /// selects the successor even when the accepted Create keeps its nonce.
    pub(crate) fn preview_source_project_admission_reservation_v1(
        &self,
        client_nonce: [u8; 16],
        project: ProjectId,
        names: ProtectedJournalNamesV1,
    ) -> Result<SourceProjectAdmissionReservationV1, JournalError> {
        source_domain_policy_hold::ensure_source_domain(self)?;
        if client_nonce == [0; 16]
            || project.as_bytes() == &[0; 16]
            || self.protected_writer_physical_names_v1()? != names
            || self
                .source_domain_policy_hold_v1()?
                .is_some_and(|hold| hold.is_held())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let rows = current_rows(&self.state)?;
        if let Some(prior) = rows.reservation {
            if prior.client_nonce == client_nonce
                && prior.project == project
                && prior.names == names
                && rows.cancellation.is_none()
                && rows.retirement_ack.is_none()
            {
                return Ok(prior);
            }
            if rows.retirement_ack.is_none() {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(SourceProjectAdmissionReservationV1 {
            issue: rows
                .reservation
                .map(|row| {
                    row.issue
                        .checked_add(1)
                        .ok_or(JournalError::ProtectedBoundary)
                })
                .transpose()?
                .unwrap_or(1),
            client_nonce,
            project,
            names,
        })
    }

    /// Reserves Source capacity and fences unrelated writes before Root stages.
    ///
    /// The caller must have preflighted reservation, challenge, settlement, and ACK
    /// under this writer. Identical replay is read-only; another nonce cannot
    /// supersede a pending reservation or challenge.
    pub(crate) fn record_source_project_admission_reservation_v1(
        &mut self,
        client_nonce: [u8; 16],
        project: ProjectId,
        names: ProtectedJournalNamesV1,
    ) -> Result<SourceProjectAdmissionReservationV1, JournalError> {
        let row =
            self.preview_source_project_admission_reservation_v1(client_nonce, project, names)?;
        let rows = current_rows(&self.state)?;
        if rows.reservation == Some(row) {
            return Ok(row);
        }
        let transaction =
            reservation_transaction(row, rows.settlement.is_some(), rows.cancellation.is_some())?;
        self.commit_source_project_admission_transition(
            &transaction,
            SourceProjectAdmissionTransition::Reserve,
        )?;
        if current_reservation(&self.state)? != Some(row)
            || self.protected_writer_physical_names_v1()? != names
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }

    /// Replays the current Source challenge and exact local retirement state.
    pub(crate) fn source_project_admission_status_v1(
        &self,
    ) -> Result<Option<(SourceProjectAdmissionChallengeV1, bool)>, JournalError> {
        let rows = current_rows(&self.state)?;
        Ok(rows.challenge.map(|row| (row, rows.settlement.is_some())))
    }

    /// Preflights reservation, challenge, terminal, and ACK writes before Root stages.
    ///
    /// The retained Source writer prevents a competing Source transaction from
    /// spending the capacity between this check and Root-last submission.
    pub(crate) fn preflight_source_project_admission_capacity_v1(
        &mut self,
        client_nonce: [u8; 16],
        project: ProjectId,
        ancestry: ObjectDigest,
        names: ProtectedJournalNamesV1,
    ) -> Result<(), JournalError> {
        source_domain_policy_hold::ensure_source_domain(self)?;
        if client_nonce == [0; 16]
            || project.as_bytes() == &[0; 16]
            || ancestry.as_bytes() == &[0; 32]
            || self.protected_writer_physical_names_v1()? != names
            || self
                .source_domain_policy_hold_v1()?
                .is_some_and(|hold| hold.is_held())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let rows = current_rows(&self.state)?;
        let prior = rows.challenge;
        let settlement = rows.settlement;
        let prior_reservation = rows.reservation;
        let cancellation = rows.cancellation;
        if prior_reservation.is_some() && rows.retirement_ack.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        let issue = prior_reservation
            .map(|row| {
                row.issue
                    .checked_add(1)
                    .ok_or(JournalError::ProtectedBoundary)
            })
            .transpose()?
            .unwrap_or(1);
        let reservation = SourceProjectAdmissionReservationV1 {
            issue,
            client_nonce,
            project,
            names,
        };
        let challenge = SourceProjectAdmissionChallengeV1 {
            kind: SourceProjectAdmissionChallengeKindV1::Admission,
            issue,
            nonce: [11; 16],
            cut: ObjectDigest::from_bytes([12; 32]),
            project,
            ancestry,
            stage: ObjectDigest::from_bytes([13; 32]),
            names,
        };
        let reservation_write = reservation_transaction(
            reservation,
            prior.is_some() && settlement.is_some(),
            cancellation.is_some(),
        )?;
        let acquisition = acquisition_transaction(challenge)?;
        let settlement_row = SourceProjectAdmissionSettlementV1 {
            issue,
            challenge: challenge.record_digest(),
            stage: challenge.stage(),
            outcome: ObjectDigest::from_bytes([14; 32]),
        };
        let terminal = SourceProjectAdmissionTerminalV1 {
            reservation,
            challenge: Some(challenge),
            terminal: SourceProjectTerminalRecordV1::Settlement(settlement_row),
        };
        let retirement_ack = |terminal: SourceProjectAdmissionTerminalV1| {
            single_record_transaction(
                RETIREMENT_ACK_KEY,
                &SourceProjectTerminalRetirementAckV1 {
                    issue,
                    reservation: reservation.record_digest(),
                    source_terminal: terminal.source_terminal_digest(),
                    root_floor: ObjectDigest::from_bytes([16; 32]),
                }
                .encode(),
            )
        };
        self.preflight_transactions_with_capacity_scope_and_project_admission(
            &[
                reservation_write,
                acquisition,
                settlement_transaction(settlement_row)?,
                retirement_ack(terminal)?,
            ],
            None,
            false,
            false,
            Some(&[
                SourceProjectAdmissionTransition::Reserve,
                SourceProjectAdmissionTransition::Acquire,
                SourceProjectAdmissionTransition::Settle,
                SourceProjectAdmissionTransition::AcknowledgeRetirement,
            ]),
            None,
        )?;
        self.preflight_source_project_negative_capacity_v1(client_nonce, project, names)
    }

    /// Measures only real reservation, cancellation and ACK transaction sizes.
    ///
    /// The placeholders describe capacity, never durable proofs or ancestry.
    /// The same retained writer must rejoin the preview and append the actual
    /// reservation only after Root's durable denial capacity is read back.
    pub(crate) fn preflight_source_project_negative_capacity_v1(
        &mut self,
        client_nonce: [u8; 16],
        project: ProjectId,
        names: ProtectedJournalNamesV1,
    ) -> Result<(), JournalError> {
        let reservation =
            self.preview_source_project_admission_reservation_v1(client_nonce, project, names)?;
        let rows = current_rows(&self.state)?;
        if rows.reservation.is_some() && rows.retirement_ack.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        let cancellation = SourceProjectReservationCancellationV1 {
            issue: reservation.issue,
            reservation: reservation.record_digest(),
            root_marker: ObjectDigest::from_bytes([15; 32]),
        };
        let terminal = SourceProjectAdmissionTerminalV1 {
            reservation,
            challenge: None,
            terminal: SourceProjectTerminalRecordV1::Cancellation(cancellation),
        };
        let ack = SourceProjectTerminalRetirementAckV1 {
            issue: reservation.issue,
            reservation: reservation.record_digest(),
            source_terminal: terminal.source_terminal_digest(),
            root_floor: ObjectDigest::from_bytes([16; 32]),
        };
        self.preflight_transactions_with_capacity_scope_and_project_admission(
            &[
                reservation_transaction(
                    reservation,
                    rows.settlement.is_some(),
                    rows.cancellation.is_some(),
                )?,
                cancellation_transaction(cancellation)?,
                single_record_transaction(RETIREMENT_ACK_KEY, &ack.encode())?,
            ],
            None,
            false,
            false,
            Some(&[
                SourceProjectAdmissionTransition::Reserve,
                SourceProjectAdmissionTransition::CancelReservation,
                SourceProjectAdmissionTransition::AcknowledgeRetirement,
            ]),
            None,
        )
    }

    /// Spends one Root nonce under the retained fixed Source writer.
    ///
    /// Identical replay is a read-only no-op. A distinct nonce replaces the
    /// row only after exact Root-outcome settlement of the prior issue; this
    /// challenge alone never grants Root authority.
    ///
    /// # Errors
    ///
    /// Rejects a foreign writer, pending Q04 hold, invalid or replaced names,
    /// conflicting nonce replay, exhausted issue or capacity, or failed commit.
    pub(crate) fn record_source_project_admission_challenge_v1(
        &mut self,
        project: ProjectId,
        ancestry: ObjectDigest,
        nonce: [u8; 16],
        cut: ObjectDigest,
        stage: ObjectDigest,
        names: ProtectedJournalNamesV1,
    ) -> Result<SourceProjectAdmissionChallengeV1, JournalError> {
        self.record_source_project_challenge_kind_v1(
            SourceProjectAdmissionChallengeKindV1::Admission,
            project,
            ancestry,
            nonce,
            cut,
            stage,
            names,
        )
    }

    /// Records a same-size, nonauthorizing challenge when ancestry cannot be admitted.
    pub(crate) fn record_source_project_abort_only_challenge_v1(
        &mut self,
        project: ProjectId,
        nonce: [u8; 16],
        cut: ObjectDigest,
        stage: ObjectDigest,
        names: ProtectedJournalNamesV1,
    ) -> Result<SourceProjectAdmissionChallengeV1, JournalError> {
        self.record_source_project_challenge_kind_v1(
            SourceProjectAdmissionChallengeKindV1::AbortOnly,
            project,
            ObjectDigest::from_bytes([0; 32]),
            nonce,
            cut,
            stage,
            names,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record_source_project_challenge_kind_v1(
        &mut self,
        kind: SourceProjectAdmissionChallengeKindV1,
        project: ProjectId,
        ancestry: ObjectDigest,
        nonce: [u8; 16],
        cut: ObjectDigest,
        stage: ObjectDigest,
        names: ProtectedJournalNamesV1,
    ) -> Result<SourceProjectAdmissionChallengeV1, JournalError> {
        source_domain_policy_hold::ensure_source_domain(self)?;
        if self
            .source_domain_policy_hold_v1()?
            .is_some_and(|hold| hold.is_held())
            || project.as_bytes() == &[0; 16]
            || (kind == SourceProjectAdmissionChallengeKindV1::Admission
                && ancestry.as_bytes() == &[0; 32])
            || (kind == SourceProjectAdmissionChallengeKindV1::AbortOnly
                && ancestry.as_bytes() != &[0; 32])
            || nonce == [0; 16]
            || cut.as_bytes() == &[0; 32]
            || stage.as_bytes() == &[0; 32]
            || self.protected_writer_physical_names_v1()? != names
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let rows = current_rows(&self.state)?;
        let reserved = rows.reservation.ok_or(JournalError::ProtectedBoundary)?;
        if let Some(row) = rows.challenge {
            if row.kind == kind
                && row.nonce == nonce
                && row.cut == cut
                && row.project == project
                && row.ancestry == ancestry
                && row.stage == stage
                && row.names == names
            {
                return Ok(row);
            }
            return Err(JournalError::ProtectedBoundary);
        }
        if rows.settlement.is_some() || reserved.project != project || reserved.names != names {
            return Err(JournalError::ProtectedBoundary);
        }
        let row = SourceProjectAdmissionChallengeV1 {
            kind,
            issue: reserved.issue,
            nonce,
            cut,
            project,
            ancestry,
            stage,
            names,
        };
        let transaction = acquisition_transaction(row)?;
        self.commit_source_project_admission_transition(
            &transaction,
            SourceProjectAdmissionTransition::Acquire,
        )?;
        if replay_source_project_admission_challenge_v1(self)? != Some(row)
            || self.protected_writer_physical_names_v1()? != names
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }

    /// Records exactly one Source terminal after peer-checked Root replay.
    ///
    /// The opaque proof is only minted by the fixed Root socket query. An
    /// ambiguous reply must be queried again; a bare Root response is not an
    /// authority to lift the Source mutation fence. The separate history-floor
    /// ACK must also be accepted under retained Controller custody.
    ///
    /// # Errors
    ///
    /// Rejects changed Source custody, mismatched challenge/outcome, a
    /// conflicting retirement, or a failed durable commit/readback.
    pub(crate) fn settle_source_project_admission_challenge_v1(
        &mut self,
        expected: SourceProjectAdmissionChallengeV1,
        proof: RootProjectAdmissionOutcomeProofV1,
    ) -> Result<(), JournalError> {
        source_domain_policy_hold::ensure_source_domain(self)?;
        let outcome = proof.outcome();
        let rows = current_rows(&self.state)?;
        if rows.challenge != Some(expected)
            || self.protected_writer_physical_names_v1()? != expected.names()
            || outcome.project() != expected.project()
            || outcome.source_row() != expected.record_digest()
            || outcome.stage() != expected.stage()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let settlement = SourceProjectAdmissionSettlementV1 {
            issue: expected.issue(),
            challenge: expected.record_digest(),
            stage: outcome.stage(),
            outcome: outcome.record_digest(),
        };
        let prior = rows.settlement;
        if let Some(prior) = prior {
            return if prior == settlement {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            };
        }
        let transaction = settlement_transaction(settlement)?;
        self.commit_source_project_admission_transition(
            &transaction,
            SourceProjectAdmissionTransition::Settle,
        )?;
        if current_rows(&self.state)?.settlement != Some(settlement)
            || self.protected_writer_physical_names_v1()? != expected.names()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

fn reservation_transaction(
    reservation: SourceProjectAdmissionReservationV1,
    clear_prior_settlement: bool,
    clear_prior_cancellation: bool,
) -> Result<JournalTransaction, JournalError> {
    let bytes = reservation.encode();
    let mut records = vec![JournalRecord::put(
        RecordNamespace::DesiredState,
        RESERVATION_KEY.to_vec(),
        bytes.to_vec(),
    )];
    if clear_prior_settlement {
        records.push(JournalRecord::delete(
            RecordNamespace::DesiredState,
            KEY.to_vec(),
        ));
        records.push(JournalRecord::delete(
            RecordNamespace::DesiredState,
            SETTLEMENT_KEY.to_vec(),
        ));
    }
    if clear_prior_cancellation {
        records.push(JournalRecord::delete(
            RecordNamespace::DesiredState,
            CANCELLATION_KEY.to_vec(),
        ));
    }
    if clear_prior_settlement || clear_prior_cancellation {
        records.push(JournalRecord::delete(
            RecordNamespace::DesiredState,
            RETIREMENT_ACK_KEY.to_vec(),
        ));
    }
    JournalTransaction::new(transaction_id(&bytes)?, records)
}

fn acquisition_transaction(
    challenge: SourceProjectAdmissionChallengeV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(KEY, &challenge.encode())
}

fn settlement_transaction(
    settlement: SourceProjectAdmissionSettlementV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(SETTLEMENT_KEY, &settlement.encode())
}

fn cancellation_transaction(
    cancellation: SourceProjectReservationCancellationV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(CANCELLATION_KEY, &cancellation.encode())
}

fn single_record_transaction(key: &[u8], bytes: &[u8]) -> Result<JournalTransaction, JournalError> {
    JournalTransaction::new(
        transaction_id(bytes)?,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            key.to_vec(),
            bytes.to_vec(),
        )],
    )
}

fn transaction_id(bytes: &[u8]) -> Result<[u8; 16], JournalError> {
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;
    use crate::lifecycle::protected_journal_join::source_domain_journal_limits;
    use crate::policy_compiler::{
        test_root_project_reservation_cancellation_v1, test_source_project_admission_outcome_v1,
    };

    // Exercises journal fencing only; it does not mint cross-owner authority.
    fn append_retirement_ack_for_test(writer: &mut Journal) {
        let terminal = writer
            .source_project_admission_terminal_v1()
            .unwrap()
            .unwrap();
        let ack = SourceProjectTerminalRetirementAckV1 {
            issue: terminal.reservation().issue(),
            reservation: terminal.reservation().record_digest(),
            source_terminal: terminal.source_terminal_digest(),
            root_floor: ObjectDigest::from_bytes([22; 32]),
        };
        writer
            .commit_source_project_admission_transition(
                &single_record_transaction(RETIREMENT_ACK_KEY, &ack.encode()).unwrap(),
                SourceProjectAdmissionTransition::AcknowledgeRetirement,
            )
            .unwrap();
    }

    #[test]
    fn reservation_fences_crash_replay_until_exact_root_cancellation() {
        let directory = tempfile::tempdir().expect("Source directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let name = "source-domains-v1.journal";
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let names = writer.protected_writer_physical_names_v1().unwrap();
        let project = ProjectId::from_bytes([1; 16]);
        let reservation = writer
            .record_source_project_admission_reservation_v1([2; 16], project, names)
            .unwrap();
        let ordinary = JournalTransaction::new(
            [3; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"unrelated".to_vec(),
                b"value".to_vec(),
            )],
        )
        .unwrap();
        assert!(writer.commit(&ordinary).is_err());
        assert!(writer.compact().is_err());
        drop(writer);

        let (mut cold, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        assert_eq!(
            cold.source_project_admission_reservation_status_v1()
                .unwrap(),
            Some((reservation, false)),
        );
        assert!(cold.commit(&ordinary).is_err());
        let wrong = SourceProjectAdmissionReservationV1 {
            project: ProjectId::from_bytes([9; 16]),
            ..reservation
        };
        let wrong_proof = RootProjectReservationCancellationProofV1::from_test_marker(
            test_root_project_reservation_cancellation_v1(wrong),
        );
        assert!(
            cold.settle_source_project_admission_reservation_v1(reservation, wrong_proof)
                .is_err()
        );
        let marker = test_root_project_reservation_cancellation_v1(reservation);
        let proof = RootProjectReservationCancellationProofV1::from_test_marker(marker);
        cold.settle_source_project_admission_reservation_v1(reservation, proof)
            .unwrap();
        cold.settle_source_project_admission_reservation_v1(reservation, proof)
            .expect("exact cancellation replay");
        assert_eq!(
            cold.source_project_admission_reservation_status_v1()
                .unwrap(),
            Some((reservation, true)),
        );
        assert!(cold.commit(&ordinary).is_err());
        assert!(cold.compact().is_err());
        assert!(
            cold.record_source_project_admission_reservation_v1([8; 16], project, names)
                .is_err()
        );
        append_retirement_ack_for_test(&mut cold);
        cold.commit(&ordinary)
            .expect("unrelated mutation after retirement ACK");
        assert!(
            cold.record_source_project_admission_challenge_v1(
                project,
                ObjectDigest::from_bytes([4; 32]),
                [5; 16],
                ObjectDigest::from_bytes([6; 32]),
                ObjectDigest::from_bytes([7; 32]),
                names,
            )
            .is_err()
        );
        let successor = cold
            .record_source_project_admission_reservation_v1(
                reservation.client_nonce(),
                project,
                names,
            )
            .unwrap();
        assert_eq!(successor.issue(), reservation.issue() + 1);
        assert_ne!(successor.record_digest(), reservation.record_digest());
    }

    #[test]
    fn single_flight_challenge_replays_exactly_and_rejects_substitution() {
        let directory = tempfile::tempdir().expect("Source directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private Source directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let name = "source-domains-v1.journal";
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("protected Source writer");
        let names = writer
            .protected_writer_physical_names_v1()
            .expect("fixed names");
        let project = ProjectId::from_bytes([1; 16]);
        let ancestry = ObjectDigest::from_bytes([2; 32]);
        let cut = ObjectDigest::from_bytes([3; 32]);
        let stage = ObjectDigest::from_bytes([8; 32]);
        writer
            .preflight_source_project_admission_capacity_v1([7; 16], project, ancestry, names)
            .expect("reservation, challenge, and retirement capacity");
        let reserved = writer
            .record_source_project_admission_reservation_v1([7; 16], project, names)
            .expect("durable reservation");
        assert_eq!(reserved.issue(), 1);
        assert!(writer.compact().is_err());

        let first = writer
            .record_source_project_admission_challenge_v1(
                project, ancestry, [4; 16], cut, stage, names,
            )
            .expect("first durable challenge");
        assert!(
            writer
                .preflight_source_project_admission_capacity_v1([7; 16], project, ancestry, names)
                .is_err()
        );
        assert_eq!(first.issue(), 1);
        assert_eq!(
            writer
                .record_source_project_admission_challenge_v1(
                    project, ancestry, [4; 16], cut, stage, names,
                )
                .expect("identical no-op replay"),
            first
        );
        assert!(
            writer
                .record_source_project_admission_challenge_v1(
                    project, ancestry, [5; 16], cut, stage, names
                )
                .is_err()
        );
        assert!(
            writer
                .record_source_project_admission_challenge_v1(
                    project,
                    ObjectDigest::from_bytes([6; 32]),
                    [4; 16],
                    cut,
                    stage,
                    names,
                )
                .is_err()
        );
        let mut changed = first.record_bytes();
        changed[88] ^= 1;
        assert!(SourceProjectAdmissionChallengeV1::from_record_bytes(&changed).is_err());
        drop(writer);

        let (cold, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("cold Source writer");
        assert_eq!(
            replay_source_project_admission_challenge_v1(&cold).expect("typed replay"),
            Some(first)
        );
        assert_eq!(
            cold.source_project_admission_reservation_v1().unwrap(),
            Some(reserved)
        );
        let (mut signer, _) = Journal::open_read_only_protected_at_uid_for_test(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("independent read-only replay");
        assert_eq!(signer.physical_names_v1(), names);
        assert_eq!(
            replay_source_project_admission_challenge_v1(signer.journal_mut())
                .expect("signer typed replay"),
            Some(first)
        );
    }

    #[test]
    fn root_outcome_retires_exact_challenge_and_cold_replay_fences_mutation() {
        let directory = tempfile::tempdir().expect("Source directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private Source directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let name = "source-domains-v1.journal";
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("protected Source writer");
        let names = writer.protected_writer_physical_names_v1().expect("names");
        let project = ProjectId::from_bytes([1; 16]);
        let ancestry = ObjectDigest::from_bytes([2; 32]);
        let cut = ObjectDigest::from_bytes([3; 32]);
        let stage = ObjectDigest::from_bytes([8; 32]);
        writer
            .record_source_project_admission_reservation_v1([7; 16], project, names)
            .expect("durable reservation");
        let first = writer
            .record_source_project_admission_challenge_v1(
                project, ancestry, [4; 16], cut, stage, names,
            )
            .expect("durable challenge");
        let ordinary = JournalTransaction::new(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"other".to_vec(),
                b"value".to_vec(),
            )],
        )
        .expect("ordinary transaction");
        assert!(writer.commit(&ordinary).is_err());
        assert!(writer.compact().is_err());

        let other = SourceProjectAdmissionChallengeV1 {
            project: ProjectId::from_bytes([5; 16]),
            ..first
        };
        let wrong = RootProjectAdmissionOutcomeProofV1::from_test_outcome(
            test_source_project_admission_outcome_v1(other, ObjectDigest::from_bytes([6; 32])),
        );
        assert!(
            writer
                .settle_source_project_admission_challenge_v1(first, wrong)
                .is_err()
        );
        let proof = RootProjectAdmissionOutcomeProofV1::from_test_outcome(
            test_source_project_admission_outcome_v1(first, stage),
        );
        writer
            .settle_source_project_admission_challenge_v1(first, proof)
            .expect("exact Root retirement");
        writer
            .settle_source_project_admission_challenge_v1(first, proof)
            .expect("idempotent retirement");
        assert!(writer.commit(&ordinary).is_err());
        assert!(writer.compact().is_err());
        assert!(
            writer
                .record_source_project_admission_reservation_v1([8; 16], project, names)
                .is_err()
        );
        drop(writer);

        let (mut cold, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("cold Source writer");
        cold.settle_source_project_admission_challenge_v1(first, proof)
            .expect("cold exact replay");
        assert!(cold.commit(&ordinary).is_err());
        assert!(cold.compact().is_err());
        append_retirement_ack_for_test(&mut cold);
        cold.commit(&ordinary)
            .expect("ordinary mutation after Root retirement ACK");
        cold.record_source_project_admission_reservation_v1([8; 16], project, names)
            .expect("successor reservation");
        assert!(current_rows(&cold.state).unwrap().retirement_ack.is_none());
        assert!(
            cold.source_project_admission_terminal_v1()
                .unwrap()
                .is_none()
        );
        let next = cold
            .record_source_project_admission_challenge_v1(
                project,
                ancestry,
                [7; 16],
                cut,
                ObjectDigest::from_bytes([9; 32]),
                names,
            )
            .expect("successor challenge");
        assert_eq!(next.issue(), 2);
        assert!(cold.commit(&ordinary).is_err());
        assert!(
            cold.settle_source_project_admission_challenge_v1(first, proof)
                .is_err()
        );
    }

    #[test]
    fn abort_only_row_never_claims_ancestry_and_retires_exactly() {
        let directory = tempfile::tempdir().expect("Source directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private Source directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .expect("protected Source writer");
        let names = writer.protected_writer_physical_names_v1().expect("names");
        let project = ProjectId::from_bytes([1; 16]);
        let stage = ObjectDigest::from_bytes([8; 32]);
        writer
            .preflight_source_project_admission_capacity_v1(
                [7; 16],
                project,
                ObjectDigest::from_bytes([2; 32]),
                names,
            )
            .expect("capacity held before Root stage");
        writer
            .record_source_project_admission_reservation_v1([7; 16], project, names)
            .expect("durable reservation");
        assert!(
            writer
                .record_source_project_admission_challenge_v1(
                    project,
                    ObjectDigest::from_bytes([0; 32]),
                    [4; 16],
                    ObjectDigest::from_bytes([3; 32]),
                    stage,
                    names,
                )
                .is_err()
        );
        let row = writer
            .record_source_project_abort_only_challenge_v1(
                project,
                [4; 16],
                ObjectDigest::from_bytes([3; 32]),
                stage,
                names,
            )
            .expect("durable abort-only row");
        assert_eq!(row.kind(), SourceProjectAdmissionChallengeKindV1::AbortOnly);
        assert_eq!(row.ancestry().as_bytes(), &[0; 32]);
        assert!(!row.matches_current(
            row.nonce(),
            row.cut(),
            project,
            row.ancestry(),
            stage,
            names,
        ));
        assert!(
            writer
                .record_source_project_admission_challenge_v1(
                    project,
                    ObjectDigest::from_bytes([2; 32]),
                    row.nonce(),
                    row.cut(),
                    stage,
                    names,
                )
                .is_err()
        );
        let proof = RootProjectAdmissionOutcomeProofV1::from_test_outcome(
            test_source_project_admission_outcome_v1(row, stage),
        );
        writer
            .settle_source_project_admission_challenge_v1(row, proof)
            .expect("exact abort retirement");
    }

    #[test]
    fn terminal_join_rejects_missing_challenge_stage_substitution_and_foreign_ack() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let names = writer.protected_writer_physical_names_v1().unwrap();
        let reservation = writer
            .record_source_project_admission_reservation_v1(
                [2; 16],
                ProjectId::from_bytes([1; 16]),
                names,
            )
            .unwrap();
        let challenge = writer
            .record_source_project_admission_challenge_v1(
                reservation.project(),
                ObjectDigest::from_bytes([3; 32]),
                [4; 16],
                ObjectDigest::from_bytes([5; 32]),
                ObjectDigest::from_bytes([6; 32]),
                names,
            )
            .unwrap();
        let settlement = SourceProjectAdmissionSettlementV1 {
            issue: challenge.issue(),
            challenge: challenge.record_digest(),
            stage: challenge.stage(),
            outcome: ObjectDigest::from_bytes([7; 32]),
        };
        writer
            .commit_source_project_admission_transition(
                &settlement_transaction(settlement).unwrap(),
                SourceProjectAdmissionTransition::Settle,
            )
            .unwrap();
        let terminal = writer
            .source_project_admission_terminal_v1()
            .unwrap()
            .unwrap();
        let ack = SourceProjectTerminalRetirementAckV1 {
            issue: reservation.issue(),
            reservation: reservation.record_digest(),
            source_terminal: terminal.source_terminal_digest(),
            root_floor: ObjectDigest::from_bytes([8; 32]),
        };
        for foreign in [
            SourceProjectTerminalRetirementAckV1 { issue: 2, ..ack },
            SourceProjectTerminalRetirementAckV1 {
                reservation: ObjectDigest::from_bytes([9; 32]),
                ..ack
            },
            SourceProjectTerminalRetirementAckV1 {
                source_terminal: ObjectDigest::from_bytes([9; 32]),
                ..ack
            },
        ] {
            let mut state = writer.state.clone();
            state.insert(
                (RecordNamespace::DesiredState, RETIREMENT_ACK_KEY.to_vec()),
                foreign.encode().to_vec(),
            );
            assert!(current_rows(&state).is_err());
        }
        let mut missing = writer.state.clone();
        missing.remove(&(RecordNamespace::DesiredState, KEY.to_vec()));
        assert!(current_rows(&missing).is_err());
        let mut wrong_stage = writer.state.clone();
        wrong_stage.insert(
            (RecordNamespace::DesiredState, SETTLEMENT_KEY.to_vec()),
            SourceProjectAdmissionSettlementV1 {
                stage: ObjectDigest::from_bytes([10; 32]),
                ..settlement
            }
            .encode()
            .to_vec(),
        );
        assert!(current_rows(&wrong_stage).is_err());
        let mut malformed = ack.encode();
        malformed[88] ^= 1;
        assert!(SourceProjectTerminalRetirementAckV1::decode(&malformed).is_err());
    }

    #[test]
    fn reservation_version_two_rejects_checksumming_legacy_history() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let names = writer.protected_writer_physical_names_v1().unwrap();
        let row = writer
            .record_source_project_admission_reservation_v1(
                [2; 16],
                ProjectId::from_bytes([1; 16]),
                names,
            )
            .unwrap();
        assert_eq!(&row.record_bytes()[8..10], &2_u16.to_be_bytes());
        let mut legacy = row.record_bytes();
        legacy[8..10].copy_from_slice(&1_u16.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(RESERVATION_DOMAIN)
            .chain_update(&legacy[..104])
            .finalize();
        legacy[104..].copy_from_slice(&checksum);
        assert!(SourceProjectAdmissionReservationV1::from_record_bytes(&legacy).is_err());
    }

    #[test]
    fn preflight_reserves_terminal_ack_before_any_source_write() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let mut limits = source_domain_journal_limits();
        limits.maximum_transactions = 3;
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            limits,
            uid,
        )
        .unwrap();
        let names = writer.protected_writer_physical_names_v1().unwrap();
        let before = writer.snapshot_sequence();
        assert!(
            writer
                .preflight_source_project_admission_capacity_v1(
                    [2; 16],
                    ProjectId::from_bytes([1; 16]),
                    ObjectDigest::from_bytes([3; 32]),
                    names,
                )
                .is_err()
        );
        assert_eq!(writer.snapshot_sequence(), before);
        assert!(
            writer
                .source_project_admission_reservation_v1()
                .unwrap()
                .is_none()
        );
        writer.limits.maximum_transactions = 4;
        writer
            .preflight_source_project_admission_capacity_v1(
                [2; 16],
                ProjectId::from_bytes([1; 16]),
                ObjectDigest::from_bytes([3; 32]),
                names,
            )
            .unwrap();
        assert_eq!(writer.snapshot_sequence(), before);
    }

    #[test]
    fn negative_preflight_reserves_three_real_source_cuts_without_ancestry_or_append() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let mut limits = source_domain_journal_limits();
        limits.maximum_transactions = 2;
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            limits,
            uid,
        )
        .unwrap();
        let names = writer.protected_writer_physical_names_v1().unwrap();
        let project = ProjectId::from_bytes([73; 16]);
        let before = writer.snapshot_sequence();
        assert!(
            writer
                .preflight_source_project_negative_capacity_v1([74; 16], project, names)
                .is_err()
        );
        assert_eq!(writer.snapshot_sequence(), before);
        assert!(
            writer
                .source_project_admission_reservation_v1()
                .unwrap()
                .is_none()
        );
        writer.limits.maximum_transactions = 3;
        writer
            .preflight_source_project_negative_capacity_v1([74; 16], project, names)
            .unwrap();
        assert_eq!(writer.snapshot_sequence(), before);
        let reservation = writer
            .record_source_project_admission_reservation_v1([74; 16], project, names)
            .unwrap();
        let marker = test_root_project_reservation_cancellation_v1(reservation);
        writer
            .settle_source_project_admission_reservation_v1(
                reservation,
                RootProjectReservationCancellationProofV1::from_test_marker(marker),
            )
            .unwrap();
        assert!(
            writer
                .source_project_admission_status_v1()
                .unwrap()
                .is_none()
        );
        assert!(
            writer
                .preview_source_project_admission_reservation_v1([74; 16], project, names)
                .is_err()
        );
        assert!(writer.compact().is_err());
        append_retirement_ack_for_test(&mut writer);
        assert_eq!(writer.committed_transactions, 3);
        // This test-only exact ACK helper models the final authority join; it
        // is not a production Root/Controller proof or an installed issuer.
        assert_eq!(
            writer
                .preview_source_project_admission_reservation_v1([74; 16], project, names)
                .unwrap()
                .issue(),
            reservation.issue() + 1
        );
    }

    #[test]
    fn same_nonce_abort_retry_advances_only_after_exact_ack_and_cold_replay() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let name = "source-domains-v1.journal";
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        let names = writer.protected_writer_physical_names_v1().unwrap();
        let project = ProjectId::from_bytes([1; 16]);
        let nonce = [2; 16];
        let reservation = writer
            .record_source_project_admission_reservation_v1(nonce, project, names)
            .unwrap();
        assert_eq!(
            writer
                .preview_source_project_admission_reservation_v1(nonce, project, names)
                .unwrap(),
            reservation
        );
        let challenge = writer
            .record_source_project_admission_challenge_v1(
                project,
                ObjectDigest::from_bytes([3; 32]),
                [4; 16],
                ObjectDigest::from_bytes([5; 32]),
                ObjectDigest::from_bytes([6; 32]),
                names,
            )
            .unwrap();
        let outcome = test_source_project_admission_outcome_v1(challenge, challenge.stage());
        assert_eq!(
            outcome.kind(),
            crate::policy_compiler::RootProjectAdmissionOutcomeKindV1::Aborted
        );
        writer
            .settle_source_project_admission_challenge_v1(
                challenge,
                RootProjectAdmissionOutcomeProofV1::from_test_outcome(outcome),
            )
            .unwrap();
        assert_eq!(
            writer
                .preview_source_project_admission_reservation_v1(nonce, project, names)
                .unwrap(),
            reservation
        );
        drop(writer);

        let (mut cold, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        assert_eq!(
            cold.preview_source_project_admission_reservation_v1(nonce, project, names)
                .unwrap(),
            reservation
        );
        let terminal = cold
            .source_project_admission_terminal_v1()
            .unwrap()
            .unwrap();
        let foreign = SourceProjectTerminalRetirementAckV1 {
            issue: reservation.issue(),
            reservation: reservation.record_digest(),
            source_terminal: ObjectDigest::from_bytes([9; 32]),
            root_floor: ObjectDigest::from_bytes([10; 32]),
        };
        let before = fs::read(directory.path().join(name)).unwrap();
        assert!(
            cold.commit_source_project_admission_transition(
                &single_record_transaction(RETIREMENT_ACK_KEY, &foreign.encode()).unwrap(),
                SourceProjectAdmissionTransition::AcknowledgeRetirement,
            )
            .is_err()
        );
        assert_eq!(fs::read(directory.path().join(name)).unwrap(), before);
        assert_eq!(
            cold.source_project_admission_terminal_v1().unwrap(),
            Some(terminal)
        );
        assert_eq!(
            cold.preview_source_project_admission_reservation_v1(nonce, project, names)
                .unwrap(),
            reservation
        );
        append_retirement_ack_for_test(&mut cold);
        let next = cold
            .preview_source_project_admission_reservation_v1(nonce, project, names)
            .unwrap();
        assert_eq!(next.issue(), reservation.issue() + 1);
        assert_eq!(next.client_nonce(), nonce);
        assert_ne!(next.record_digest(), reservation.record_digest());
        drop(cold);

        let (mut recovered, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .unwrap();
        assert_eq!(
            recovered
                .preview_source_project_admission_reservation_v1(nonce, project, names)
                .unwrap(),
            next
        );
        assert_eq!(
            recovered
                .record_source_project_admission_reservation_v1(nonce, project, names)
                .unwrap(),
            next
        );
        let rows = current_rows(&recovered.state).unwrap();
        assert!(rows.retirement_ack.is_none());
        assert!(rows.terminal().is_none());
        assert_eq!(rows.reservation, Some(next));
    }
}
