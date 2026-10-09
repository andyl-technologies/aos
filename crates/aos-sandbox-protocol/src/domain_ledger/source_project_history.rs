//! Owns the complete canonical Source project-admission history DATA.
//!
//! Five fixed rows share one terminal tag and full historical join. Decoding
//! checks their existing framing, canonical fields and domain-separated hashes;
//! it neither authenticates signatures nor acquires current protected custody.
//! Native selection, mutation fences, Root proofs and the held Controller
//! acceptance loan remain with their actual upper owners.
//!
//! Each row has an eight-byte magic, BE version, reserved header bytes and a
//! domain-separated SHA-256 checksum. The established fixed layouts are:
//!
//! ```text
//! AOSQPV01 v2 (136): issue | nonce | project | names | checksum
//! AOSQPA01 v2 (232): kind | issue | nonce | cut | project | ancestry |
//!                    stage | names | checksum
//! AOSQPC02 v1 (120): issue | reservation | Root cancellation | checksum
//! AOSQPC01 v1 (152): issue | challenge | stage | Root outcome | checksum
//! AOSQPT01 v1 (152): issue | reservation | Source terminal | Root floor | checksum
//! terminal transport: settlement, or cancellation followed by 32 zero bytes
//! ```
//!
//! Terminal hashing covers the actual unpadded row. Unchecked constructors and
//! encoders preserve supplied DATA, including negative fixtures; joined-history
//! validation remains an explicit operation rather than a native authority grant.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::ProtectedHistoryDataErrorV1;
use super::protected_names::ProtectedJournalNamesV1;

const MAGIC: &[u8; 8] = b"AOSQPA01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission-challenge.v1\0";
const RECORD_BYTES: usize = 232;
const RESERVATION_MAGIC: &[u8; 8] = b"AOSQPV01";
/// Defines the established reservation checksum domain, including its terminator.
pub const RESERVATION_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission-reservation.v1\0";
const RESERVATION_BYTES: usize = 136;
const CANCELLATION_MAGIC: &[u8; 8] = b"AOSQPC02";
const CANCELLATION_DOMAIN: &[u8] = b"aos.sandbox.source-project-reservation-cancellation.v1\0";
const CANCELLATION_BYTES: usize = 120;
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

const SETTLEMENT_MAGIC: &[u8; 8] = b"AOSQPC01";
const SETTLEMENT_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission-settlement.v1\0";
const SETTLEMENT_BYTES: usize = 152;

/// Bounds a canonical Source settlement, or a zero-padded cancellation.
pub const SOURCE_PROJECT_ADMISSION_TERMINAL_BYTES_V1: usize = SETTLEMENT_BYTES;

/// Describes a historical Source terminal retirement ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceProjectTerminalRetirementAckV1 {
    issue: u64,
    reservation: ObjectDigest,
    source_terminal: ObjectDigest,
    root_floor: ObjectDigest,
}

impl SourceProjectTerminalRetirementAckV1 {
    /// Assembles unchecked historical fields without validating custody or joins.
    pub const fn from_historical_fields(
        issue: u64,
        reservation: ObjectDigest,
        source_terminal: ObjectDigest,
        root_floor: ObjectDigest,
    ) -> Self {
        Self {
            issue,
            reservation,
            source_terminal,
            root_floor,
        }
    }

    /// Returns the historical Source admission issue.
    pub const fn issue(self) -> u64 {
        self.issue
    }

    /// Returns the digest of the historical reservation row.
    pub const fn reservation(self) -> ObjectDigest {
        self.reservation
    }

    /// Returns the digest of the actual unpadded Source terminal.
    pub const fn source_terminal(self) -> ObjectDigest {
        self.source_terminal
    }

    /// Returns the retained Root history-floor digest.
    pub const fn root_floor(self) -> ObjectDigest {
        self.root_floor
    }

    /// Encodes the fixed historical fields without validating their claims.
    pub fn encode(self) -> [u8; RETIREMENT_ACK_BYTES] {
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

    /// Decodes canonical historical DATA without authenticating custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, fields or canonical checksum bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != RETIREMENT_ACK_BYTES
            || bytes.get(..8) != Some(RETIREMENT_ACK_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(row)
    }
}

/// Distinguishes the two established historical Source terminal rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceProjectTerminalRecordV1 {
    /// Carries a historical settlement after a Root outcome.
    Settlement(SourceProjectAdmissionSettlementV1),
    /// Carries a historical cancellation before challenge acquisition.
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
    /// Assembles unchecked historical fields without validating custody or joins.
    pub const fn from_historical_fields(
        reservation: SourceProjectAdmissionReservationV1,
        challenge: Option<SourceProjectAdmissionChallengeV1>,
        terminal: SourceProjectTerminalRecordV1,
    ) -> Self {
        Self {
            reservation,
            challenge,
            terminal,
        }
    }

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

    /// Decodes a padded terminal and checks its complete historical row join.
    ///
    /// # Errors
    ///
    /// Rejects malformed rows, cancellation padding or conflicting history.
    pub fn from_record_parts(
        reservation: SourceProjectAdmissionReservationV1,
        challenge: Option<SourceProjectAdmissionChallengeV1>,
        bytes: &[u8],
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        };
        let rows = SourceProjectAdmissionHistoryV1 {
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
        rows.terminal()
            .ok_or(ProtectedHistoryDataErrorV1::Malformed)
    }
}

/// Describes a historical cancellation of an unconsumed Source reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceProjectReservationCancellationV1 {
    issue: u64,
    reservation: ObjectDigest,
    root_marker: ObjectDigest,
}

impl SourceProjectReservationCancellationV1 {
    /// Assembles unchecked historical fields without validating custody or joins.
    pub const fn from_historical_fields(
        issue: u64,
        reservation: ObjectDigest,
        root_marker: ObjectDigest,
    ) -> Self {
        Self {
            issue,
            reservation,
            root_marker,
        }
    }

    /// Returns the historical Source admission issue.
    pub const fn issue(self) -> u64 {
        self.issue
    }

    /// Returns the digest of the historical reservation row.
    pub const fn reservation(self) -> ObjectDigest {
        self.reservation
    }

    /// Encodes the fixed historical fields without validating their claims.
    pub fn encode(self) -> [u8; CANCELLATION_BYTES] {
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

    /// Decodes canonical historical DATA without authenticating custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, fields or canonical checksum bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != CANCELLATION_BYTES
            || bytes.get(..8) != Some(CANCELLATION_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(row)
    }
}

/// Describes a historical settlement of a Source challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceProjectAdmissionSettlementV1 {
    issue: u64,
    challenge: ObjectDigest,
    stage: ObjectDigest,
    outcome: ObjectDigest,
}

impl SourceProjectAdmissionSettlementV1 {
    /// Assembles unchecked historical fields without validating custody or joins.
    pub const fn from_historical_fields(
        issue: u64,
        challenge: ObjectDigest,
        stage: ObjectDigest,
        outcome: ObjectDigest,
    ) -> Self {
        Self {
            issue,
            challenge,
            stage,
            outcome,
        }
    }

    /// Returns the historical Source admission issue.
    pub const fn issue(self) -> u64 {
        self.issue
    }

    /// Returns the digest of the historical challenge row.
    pub const fn challenge(self) -> ObjectDigest {
        self.challenge
    }

    /// Returns the retained Root stage digest.
    pub const fn stage(self) -> ObjectDigest {
        self.stage
    }

    /// Returns the retained Root outcome digest.
    pub const fn outcome(self) -> ObjectDigest {
        self.outcome
    }

    /// Encodes the fixed historical fields without validating their claims.
    pub fn encode(self) -> [u8; SETTLEMENT_BYTES] {
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

    /// Decodes canonical historical DATA without authenticating custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, fields or canonical checksum bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != SETTLEMENT_BYTES
            || bytes.get(..8) != Some(SETTLEMENT_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(row)
    }

    /// Compares historical settlement issue and challenge digest.
    pub fn matches(self, challenge: SourceProjectAdmissionChallengeV1) -> bool {
        self.issue == challenge.issue && self.challenge == challenge.record_digest()
    }
}

/// Bounds the canonical Source project-admission challenge row.
pub const SOURCE_PROJECT_ADMISSION_CHALLENGE_BYTES_V1: usize = RECORD_BYTES;

/// Bounds the canonical pre-stage Source reservation row.
pub const SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1: usize = RESERVATION_BYTES;

/// Describes a retained Source reservation for historical readback.
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
    /// Assembles unchecked historical fields without validating custody or joins.
    pub const fn from_historical_fields(
        issue: u64,
        client_nonce: [u8; 16],
        project: ProjectId,
        names: ProtectedJournalNamesV1,
    ) -> Self {
        Self {
            issue,
            client_nonce,
            project,
            names,
        }
    }

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
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        Self::decode(bytes)
    }

    /// Encodes the fixed historical fields without validating their claims.
    pub fn encode(self) -> [u8; RESERVATION_BYTES] {
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

    /// Decodes canonical historical DATA without authenticating custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, fields or canonical checksum bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != RESERVATION_BYTES
            || bytes.get(..8) != Some(RESERVATION_MAGIC.as_slice())
            || bytes.get(8..10) != Some(2_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
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
    /// Assembles unchecked historical fields without validating custody or joins.
    #[allow(clippy::too_many_arguments)]
    pub const fn from_historical_fields(
        kind: SourceProjectAdmissionChallengeKindV1,
        issue: u64,
        nonce: [u8; 16],
        cut: ObjectDigest,
        project: ProjectId,
        ancestry: ObjectDigest,
        stage: ObjectDigest,
        names: ProtectedJournalNamesV1,
    ) -> Self {
        Self {
            kind,
            issue,
            nonce,
            cut,
            project,
            ancestry,
            stage,
            names,
        }
    }

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
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        Self::decode(bytes)
    }

    /// Encodes the fixed historical fields without validating their claims.
    pub fn encode(self) -> [u8; RECORD_BYTES] {
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

    /// Decodes canonical historical DATA without authenticating custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, fields or canonical checksum bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let row = Self {
            kind: match bytes[10] {
                1 => SourceProjectAdmissionChallengeKindV1::Admission,
                2 => SourceProjectAdmissionChallengeKindV1::AbortOnly,
                _ => return Err(ProtectedHistoryDataErrorV1::Malformed),
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(row)
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProtectedHistoryDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(ProtectedHistoryDataErrorV1::Malformed)
}

/// Carries the five historical Source row claims without currentness custody.
#[derive(Clone, Copy)]
pub struct SourceProjectAdmissionHistoryV1 {
    reservation: Option<SourceProjectAdmissionReservationV1>,
    cancellation: Option<SourceProjectReservationCancellationV1>,
    challenge: Option<SourceProjectAdmissionChallengeV1>,
    settlement: Option<SourceProjectAdmissionSettlementV1>,
    retirement_ack: Option<SourceProjectTerminalRetirementAckV1>,
}

impl SourceProjectAdmissionHistoryV1 {
    /// Assembles unchecked historical fields without validating custody or joins.
    pub const fn from_historical_fields(
        reservation: Option<SourceProjectAdmissionReservationV1>,
        cancellation: Option<SourceProjectReservationCancellationV1>,
        challenge: Option<SourceProjectAdmissionChallengeV1>,
        settlement: Option<SourceProjectAdmissionSettlementV1>,
        retirement_ack: Option<SourceProjectTerminalRetirementAckV1>,
    ) -> Self {
        Self {
            reservation,
            cancellation,
            challenge,
            settlement,
            retirement_ack,
        }
    }

    /// Returns the historical Source reservation claim.
    pub const fn reservation(self) -> Option<SourceProjectAdmissionReservationV1> {
        self.reservation
    }

    /// Returns the historical reservation-cancellation claim.
    pub const fn cancellation(self) -> Option<SourceProjectReservationCancellationV1> {
        self.cancellation
    }

    /// Returns the historical Source challenge claim.
    pub const fn challenge(self) -> Option<SourceProjectAdmissionChallengeV1> {
        self.challenge
    }

    /// Returns the historical challenge-settlement claim.
    pub const fn settlement(self) -> Option<SourceProjectAdmissionSettlementV1> {
        self.settlement
    }

    /// Returns the historical terminal-retirement ACK claim.
    pub const fn retirement_ack(self) -> Option<SourceProjectTerminalRetirementAckV1> {
        self.retirement_ack
    }

    /// Projects a historical terminal without authenticating or validating the join.
    ///
    /// Returns None for a missing reservation or ambiguous terminal rows.
    pub fn terminal(self) -> Option<SourceProjectAdmissionTerminalV1> {
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

    /// Checks the complete historical challenge, terminal and ACK relationships.
    ///
    /// An all-absent history is permitted; this check creates no currentness proof.
    ///
    /// # Errors
    ///
    /// Rejects conflicting or missing rows required by another supplied claim.
    pub fn require_joined(self) -> Result<(), ProtectedHistoryDataErrorV1> {
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
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }
}
