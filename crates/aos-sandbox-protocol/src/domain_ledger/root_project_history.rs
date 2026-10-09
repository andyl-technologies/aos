//! Owns passive Root cancellation, outcome and terminal-floor DATA.
//!
//! Historical constructors assemble unchecked scalar fields. Parsers validate
//! canonical rows but do not authenticate a Root peer, retain a writer, or
//! authorize admission, cancellation, append, or retirement. Native joins and
//! committed/aborted decision factories remain with the Root owner.
//!
//! All integers use big-endian encoding. Each row ends with its original
//! domain-separated SHA-256 checksum over the preceding bytes:
//!
//! ```text
//! cancellation[112]: AOSQPX01 | version:u16=1 | reserved[6]=0 |
//!   reservation:32 | client-nonce:16 | project:16 | checksum:32
//! outcome[312]: AOSQPO01 | version:u16=1 | reserved[6]=0 | stage:32 |
//!   kind:u8 | reserved[7]=0 | Source-row:32 | Controller-packet:32 | operation:16 |
//!   sandbox:16 | source-commitment:32 | project:16 | project-packet:32 |
//!   project-input:32 | client-nonce:16 | checksum:32
//! floor[392]: AOSQPF01 | version:u16=1 | kind:u8 | reserved[5]=0 | issue:u64 |
//!   reservation:32 | challenge:32 | Source-terminal:32 | Root-terminal:32 |
//!   Controller-acceptance:32 | Source-pin:32 | operation:16 | sandbox:16 |
//!   project:16 | source-commitment:32 | client-nonce:16 | fixed-names:48 |
//!   checksum:32
//! ```
//!
//! Floor names are decoded before sentinel and checksum checks. This preserves
//! the distinct names failure even when another row claim is also invalid.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::protected_names::ProtectedJournalNamesV1;

/// Reports the original Root row or physical-name failure without native custody.
#[derive(Debug, thiserror::Error)]
pub enum RootProjectHistoryDataErrorV1 {
    /// Framing, scalar claims, terminal class, or canonical checksum is invalid.
    #[error("invalid Root project history DATA")]
    InvalidHead,
    /// A historical physical-name pair is malformed.
    #[error(transparent)]
    Names(#[from] super::ProtectedHistoryDataErrorV1),
}

const OUTCOME_MAGIC: &[u8; 8] = b"AOSQPO01";
const OUTCOME_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-outcome.v1\0";
const OUTCOME_BYTES: usize = 312;
const CLIENT_NONCE_DOMAIN: &[u8] = b"aos.sandbox.policy-project-admission-client.v1\0";
const RESERVATION_CANCELLATION_MAGIC: &[u8; 8] = b"AOSQPX01";
/// Supplies the canonical cancellation domain also used by Root's transaction hash.
pub const RESERVATION_CANCELLATION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-project-reservation-cancellation.v1\0";
const RESERVATION_CANCELLATION_BYTES: usize = 112;

const MAGIC: &[u8; 8] = b"AOSQPF01";
const DOMAIN: &[u8] = b"aos.sandbox.policy-project-history-floor.v1\0";
/// Gives the fixed historical floor width used by the Root socket contract.
pub const ROOT_PROJECT_HISTORY_FLOOR_BYTES_V1: usize = 392;

/// Retains Root's irreversible refusal to stage one Source reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProjectReservationCancellationV1 {
    reservation: ObjectDigest,
    client_nonce: [u8; 16],
    project: ProjectId,
}

impl RootProjectReservationCancellationV1 {
    /// Assembles unchecked historical fields without granting cancellation authority.
    pub const fn from_historical_fields(
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
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, RootProjectHistoryDataErrorV1> {
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

    fn decode(bytes: &[u8]) -> Result<Self, RootProjectHistoryDataErrorV1> {
        if bytes.len() != RESERVATION_CANCELLATION_BYTES
            || bytes.get(..8) != Some(RESERVATION_CANCELLATION_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(RootProjectHistoryDataErrorV1::InvalidHead);
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
            return Err(RootProjectHistoryDataErrorV1::InvalidHead);
        }
        Ok(row)
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
    /// Assembles unchecked historical fields without deciding a native Root outcome.
    pub const fn from_historical_fields(
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
    ) -> Self {
        Self {
            stage,
            kind,
            source_row,
            controller_packet,
            operation,
            sandbox,
            source_commitment,
            project,
            project_packet,
            project_input,
            client_nonce,
        }
    }

    /// Returns the retained Controller packet digest, or zero for an abort.
    pub const fn controller_packet(self) -> ObjectDigest {
        self.controller_packet
    }

    /// Returns the signed project packet digest retained by the original stage.
    pub const fn project_packet(self) -> ObjectDigest {
        self.project_packet
    }

    /// Returns the immutable project input digest retained by the original stage.
    pub const fn project_input(self) -> ObjectDigest {
        self.project_input
    }

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
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, RootProjectHistoryDataErrorV1> {
        Self::decode(bytes)
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

    fn decode(bytes: &[u8]) -> Result<Self, RootProjectHistoryDataErrorV1> {
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
            return Err(RootProjectHistoryDataErrorV1::InvalidHead);
        }
        let kind = match bytes[48] {
            1 => RootProjectAdmissionOutcomeKindV1::Committed,
            2 => RootProjectAdmissionOutcomeKindV1::Aborted,
            _ => return Err(RootProjectHistoryDataErrorV1::InvalidHead),
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
            return Err(RootProjectHistoryDataErrorV1::InvalidHead);
        }
        Ok(row)
    }
}

/// Distinguishes the exact historical terminal covered by one Root floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootProjectHistoryTerminalKindV1 {
    /// The exact signed project packet/input was admitted.
    Committed,
    /// The staged attempt was durably abandoned.
    Aborted,
    /// The prospective Source reservation was permanently denied staging.
    CanceledReservation,
}

impl RootProjectHistoryTerminalKindV1 {
    /// Returns the established terminal tag used by floor and Controller formats.
    pub const fn byte(self) -> u8 {
        match self {
            Self::Committed => 1,
            Self::Aborted => 2,
            Self::CanceledReservation => 3,
        }
    }

    /// Decodes an established terminal tag, rejecting every unassigned byte.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Committed),
            2 => Some(Self::Aborted),
            3 => Some(Self::CanceledReservation),
            _ => None,
        }
    }
}

/// Retains a decoded historical join without establishing Root transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProjectHistoryFloorV1 {
    kind: RootProjectHistoryTerminalKindV1,
    issue: u64,
    reservation: ObjectDigest,
    challenge: ObjectDigest,
    source_terminal: ObjectDigest,
    root_terminal: ObjectDigest,
    controller_acceptance: ObjectDigest,
    source_pin: ObjectDigest,
    operation: [u8; 16],
    sandbox: [u8; 16],
    project: ProjectId,
    source_commitment: ObjectDigest,
    client_nonce: [u8; 16],
    names: ProtectedJournalNamesV1,
}

impl RootProjectHistoryFloorV1 {
    /// Assembles unchecked historical fields without validating joins or custody.
    pub const fn from_historical_fields(
        kind: RootProjectHistoryTerminalKindV1,
        issue: u64,
        reservation: ObjectDigest,
        challenge: ObjectDigest,
        source_terminal: ObjectDigest,
        root_terminal: ObjectDigest,
        controller_acceptance: ObjectDigest,
        source_pin: ObjectDigest,
        operation: [u8; 16],
        sandbox: [u8; 16],
        project: ProjectId,
        source_commitment: ObjectDigest,
        client_nonce: [u8; 16],
        names: ProtectedJournalNamesV1,
    ) -> Self {
        Self {
            kind,
            issue,
            reservation,
            challenge,
            source_terminal,
            root_terminal,
            controller_acceptance,
            source_pin,
            operation,
            sandbox,
            project,
            source_commitment,
            client_nonce,
            names,
        }
    }

    /// Returns the historical decision class, not admission readiness.
    pub const fn kind(self) -> RootProjectHistoryTerminalKindV1 {
        self.kind
    }

    /// Returns the exact monotonically retired Source issue.
    pub const fn issue(self) -> u64 {
        self.issue
    }

    /// Returns the canonical Source reservation commitment.
    pub const fn reservation_digest(self) -> ObjectDigest {
        self.reservation
    }

    /// Returns the challenged Source row commitment, or zero for cancellation.
    pub const fn challenge_digest(self) -> ObjectDigest {
        self.challenge
    }

    /// Returns the canonical Source settlement or cancellation commitment.
    pub const fn source_terminal_digest(self) -> ObjectDigest {
        self.source_terminal
    }

    /// Returns the exact historical Root outcome or cancellation commitment.
    pub const fn root_terminal_digest(self) -> ObjectDigest {
        self.root_terminal
    }

    /// Returns the accepted original-Effect metadata commitment at Controller.
    pub const fn controller_acceptance_digest(self) -> ObjectDigest {
        self.controller_acceptance
    }

    /// Returns Root's immutable Source-only signer pin commitment.
    pub const fn source_pin_digest(self) -> ObjectDigest {
        self.source_pin
    }

    /// Returns the immutable original Create operation.
    pub const fn operation(self) -> [u8; 16] {
        self.operation
    }

    /// Returns the immutable original child identity, including on abort.
    pub const fn sandbox(self) -> [u8; 16] {
        self.sandbox
    }

    /// Returns the exact project partition.
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the original admitted Create/project-source commitment.
    pub const fn source_commitment(self) -> ObjectDigest {
        self.source_commitment
    }

    /// Returns the original effect-owned admission nonce.
    pub const fn client_nonce(self) -> [u8; 16] {
        self.client_nonce
    }

    /// Returns the exact Source fixed-name identities covered by the floor.
    pub const fn names(self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns SHA-256 of the complete canonical historical row.
    pub fn record_digest(self) -> ObjectDigest {
        digest(&self.record_bytes())
    }

    /// Returns the canonical row without authenticating its transport.
    pub fn record_bytes(self) -> [u8; ROOT_PROJECT_HISTORY_FLOOR_BYTES_V1] {
        let mut bytes = [0; ROOT_PROJECT_HISTORY_FLOOR_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = self.kind.byte();
        bytes[16..24].copy_from_slice(&self.issue.to_be_bytes());
        for (index, field) in [
            self.reservation,
            self.challenge,
            self.source_terminal,
            self.root_terminal,
            self.controller_acceptance,
            self.source_pin,
        ]
        .iter()
        .enumerate()
        {
            let start = 24 + index * 32;
            bytes[start..start + 32].copy_from_slice(field.as_bytes());
        }
        bytes[216..232].copy_from_slice(&self.operation);
        bytes[232..248].copy_from_slice(&self.sandbox);
        bytes[248..264].copy_from_slice(self.project.as_bytes());
        bytes[264..296].copy_from_slice(self.source_commitment.as_bytes());
        bytes[296..312].copy_from_slice(&self.client_nonce);
        bytes[312..360].copy_from_slice(&self.names.to_bytes());
        let checksum = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes[..360])
            .finalize();
        bytes[360..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes historical bytes without granting append or release authority.
    ///
    /// # Errors
    ///
    /// Rejects changed framing, sentinel identities, contradictory terminal
    /// class, fixed names, or canonical checksum.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, RootProjectHistoryDataErrorV1> {
        if bytes.len() != ROOT_PROJECT_HISTORY_FLOOR_BYTES_V1
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[11..16] != [0; 5]
        {
            return Err(RootProjectHistoryDataErrorV1::InvalidHead);
        }
        let kind = RootProjectHistoryTerminalKindV1::from_byte(bytes[10])
            .ok_or(RootProjectHistoryDataErrorV1::InvalidHead)?;
        let field = |start| take::<32>(bytes, start).map(ObjectDigest::from_bytes);
        let row = Self {
            kind,
            issue: u64::from_be_bytes(take::<8>(bytes, 16)?),
            reservation: field(24)?,
            challenge: field(56)?,
            source_terminal: field(88)?,
            root_terminal: field(120)?,
            controller_acceptance: field(152)?,
            source_pin: field(184)?,
            operation: take::<16>(bytes, 216)?,
            sandbox: take::<16>(bytes, 232)?,
            project: ProjectId::from_bytes(take::<16>(bytes, 248)?),
            source_commitment: field(264)?,
            client_nonce: take::<16>(bytes, 296)?,
            names: ProtectedJournalNamesV1::from_bytes(&bytes[312..360])?,
        };
        if row.issue == 0
            || row.reservation == zero_digest()
            || row.source_terminal == zero_digest()
            || row.root_terminal == zero_digest()
            || row.controller_acceptance == zero_digest()
            || row.source_pin == zero_digest()
            || row.source_commitment == zero_digest()
            || row.operation == [0; 16]
            || row.sandbox == [0; 16]
            || row.project.as_bytes() == &[0; 16]
            || row.client_nonce == [0; 16]
            || ((kind == RootProjectHistoryTerminalKindV1::CanceledReservation)
                != (row.challenge == zero_digest()))
            || row.record_bytes().as_slice() != bytes
        {
            return Err(RootProjectHistoryDataErrorV1::InvalidHead);
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

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], RootProjectHistoryDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(RootProjectHistoryDataErrorV1::InvalidHead)
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

fn zero_digest() -> ObjectDigest {
    ObjectDigest::from_bytes([0; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_names_failure_precedes_issue_and_checksum_failures() {
        let floor = RootProjectHistoryFloorV1::from_historical_fields(
            RootProjectHistoryTerminalKindV1::Committed,
            1,
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
            [7; 16],
            [8; 16],
            ProjectId::from_bytes([9; 16]),
            ObjectDigest::from_bytes([10; 32]),
            [11; 16],
            ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
        );
        let canonical = floor.record_bytes();
        assert_eq!(
            RootProjectHistoryFloorV1::from_record_bytes(&canonical).unwrap(),
            floor
        );

        let mut bad_issue = canonical;
        bad_issue[16..24].fill(0);
        assert!(matches!(
            RootProjectHistoryFloorV1::from_record_bytes(&bad_issue),
            Err(RootProjectHistoryDataErrorV1::InvalidHead)
        ));

        let mut bad_checksum = canonical;
        bad_checksum[360] ^= 1;
        assert!(matches!(
            RootProjectHistoryFloorV1::from_record_bytes(&bad_checksum),
            Err(RootProjectHistoryDataErrorV1::InvalidHead)
        ));

        for mut competing_failure in [bad_issue, bad_checksum] {
            competing_failure[312..320].fill(0);
            assert!(matches!(
                RootProjectHistoryFloorV1::from_record_bytes(&competing_failure),
                Err(RootProjectHistoryDataErrorV1::Names(
                    super::super::ProtectedHistoryDataErrorV1::Malformed
                ))
            ));
        }
    }
}
