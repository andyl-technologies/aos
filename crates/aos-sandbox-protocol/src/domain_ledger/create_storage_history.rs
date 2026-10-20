//! Encodes nonauthorizing Create Storage V1 history envelopes.
//!
//! This owner checks fixed record, key and latest-head grammar. Bodies remain
//! borrowed, unvalidated phase DATA: decoding does not establish the stage's
//! nested schema, a current cut, original writer custody or a resource grant.
//! Native consumers must supply the complete phase-specific body validation and
//! paid receive bounds before this format is used in production.
//!
//! ```text
//! key = "create-storage-v1\0" | lane[16] | owner:u8 | revision:u64be
//! record = AOSXPR01 | version:u16be=1 | owner:u8 | state:u8 | reserved[4]=0 |
//!          lane[16] | revision:u64be | predecessor[32] | correlation[32] |
//!          body-length:u32be | body | checksum[32]
//! latest-head = revision:u64be | last-record-checksum[32]
//! ```
//!
//! Revision zero selects the latest-head key. A record's checksum covers its
//! complete header and body under the record domain. A latest head is meaningful
//! only with its matching record in the Native owner's original atomic append.
//! Cold history cannot reconstruct that owner or renew any permission.

use aos_sandbox_core::bounded_codec::{BoundedReader, ReadError};
use sha2::{Digest as _, Sha256};

/// Compares exact native transaction suffixes without granting receiving IO.
pub mod native_suffix;

mod pair;
pub use pair::{HistoryPairPreparationErrorV1, prepare_history_pair_v1};

/// Checks fixed Open, frame and indexed-transfer envelopes as passive DATA.
pub mod transport;

/// Frames actual admitted-use and signed-result transfers as passive DATA.
pub mod continuation;
pub mod controller_use;

/// Binds actual terminal outcomes and original held-owner releases as DATA.
pub mod outcome;

/// Checks the fixed first Root Open body as passive historical DATA.
pub mod root_open;

/// Commits exact Ready bytes as inert correlation DATA.
pub mod ready;

/// Frames actual current role observations without issuing authority.
pub mod current_proofs;

/// Frames Root's Use authorization DATA without issuing a resource claim.
pub mod use_authorized;
pub mod use_reserved;

/// Shares the original accepted-operation association as passive DATA.
pub mod association;

/// Checks a new Cache Held body and exact receipt as passive historical DATA.
pub mod cache_held;

/// Checks a new Source Held body and exact receipt as passive historical DATA.
pub mod source_held;

/// Frames the fresh Source CurrentCut query without creating live authority.
pub mod source_current;

/// Frames the proposed immutable assignment without issuing Ownership authority.
pub mod assignment_planned;

/// Borrows the exact original Controller Intent association as passive DATA.
pub mod controller_intent;

/// Holds the exact fixed key width, including the terminating prefix NUL.
pub const KEY_BYTES: usize = 43;
/// Holds the fixed record header and checksum overhead.
pub const RECORD_OVERHEAD_BYTES: usize = 140;
/// Holds the fixed record header width, excluding body and checksum.
pub const RECORD_HEADER_BYTES: usize = 108;
/// Holds the exact latest-head body width.
pub const HEAD_BYTES: usize = 40;

const KEY_PREFIX: &[u8; 18] = b"create-storage-v1\0";
const RECORD_MAGIC: &[u8; 8] = b"AOSXPR01";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.create-storage.record.v1\0";

/// Reports malformed or inconsistent continuation envelope DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoryErrorV1 {
    /// A fixed discriminator, owner, state or reserved field is invalid.
    #[error("Create Storage V1 envelope is malformed")]
    Malformed,
    /// A declared extent is truncated, has trailing bytes or overflows its width.
    #[error("Create Storage V1 envelope has an invalid extent")]
    Extent,
    /// A checksum does not cover the original complete envelope or bundle.
    #[error("Create Storage V1 envelope checksum differs")]
    Checksum,
    /// Lane, phase, predecessor, nonces, sequence or chunk coordinates differ.
    #[error("Create Storage V1 envelope coordinates differ")]
    Correlation,
}

/// Names one of the four independent historical record owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OwnerV1 {
    /// The original Controller continuation history.
    Controller = 1,
    /// The separately held Source history.
    Source = 2,
    /// The separately held Cache history.
    Cache = 3,
    /// The separately held Root authority history.
    Root = 4,
}

impl OwnerV1 {
    /// Decodes a closed owner code without acquiring its authority.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryErrorV1::Malformed`] for an unregistered code.
    pub fn decode(code: u8) -> Result<Self, HistoryErrorV1> {
        match code {
            1 => Ok(Self::Controller),
            2 => Ok(Self::Source),
            3 => Ok(Self::Cache),
            4 => Ok(Self::Root),
            _ => Err(HistoryErrorV1::Malformed),
        }
    }
}

/// Holds one owner-specific closed durable state code as passive DATA.
///
/// Controller states 1 through 11 are Intent, InputsReady, RootValidated,
/// UseReserved, Signed, DispatchBound, SessionReserved, OutcomeRecorded,
/// HandoffRetained, UnsentFailed and Quarantined. State 12 is AssignmentPlanned,
/// a nonauthorizing immutable proposal distinct from InputsReady. Root states
/// 1 through 7 are
/// Open, UseAuthorized, UseAdmitted, SignedBound, OutcomeRecorded, Closed and
/// Quarantined. Source and Cache states 1 through 3 are Held, Released and
/// Quarantined. Allowed semantic transitions and each body's exact schema remain
/// Native-owned; numeric state order alone never admits a successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseV1 {
    owner: OwnerV1,
    state: u8,
}

impl PhaseV1 {
    /// Checks that a state belongs to its closed owner registry.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryErrorV1::Malformed`] for zero or an unregistered state.
    pub fn new(owner: OwnerV1, state: u8) -> Result<Self, HistoryErrorV1> {
        let last = match owner {
            OwnerV1::Controller => 12,
            OwnerV1::Source | OwnerV1::Cache => 3,
            OwnerV1::Root => 7,
        };
        if state == 0 || state > last {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(Self { owner, state })
    }

    /// Returns the original decoded owner identity.
    pub const fn owner(self) -> OwnerV1 {
        self.owner
    }

    /// Returns the closed owner-specific historical state code.
    pub const fn state(self) -> u8 {
        self.state
    }
}

/// Holds an exact historical key, with revision zero reserved for its latest head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyV1 {
    lane: [u8; 16],
    owner: OwnerV1,
    revision: u64,
}

impl KeyV1 {
    /// Constructs comparison DATA for a nonzero lane and a closed owner.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryErrorV1::Malformed`] for a zero lane.
    pub fn new(lane: [u8; 16], owner: OwnerV1, revision: u64) -> Result<Self, HistoryErrorV1> {
        nonzero(&lane)?;
        Ok(Self { lane, owner, revision })
    }

    /// Decodes one exact key, retaining the zero-revision latest-head distinction.
    ///
    /// # Errors
    ///
    /// Rejects a malformed prefix, lane, owner or exact key length.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut reader = reader(bytes);
        if reader.bytes(KEY_PREFIX.len())? != KEY_PREFIX {
            return Err(HistoryErrorV1::Malformed);
        }
        let lane = reader.array()?;
        let owner = OwnerV1::decode(reader.u8()?)?;
        let revision = reader.u64()?;
        reader.finish()?;
        Self::new(lane, owner, revision)
    }

    /// Encodes the exact fixed key without allocation.
    pub fn encode(self) -> [u8; KEY_BYTES] {
        let mut bytes = [0; KEY_BYTES];
        bytes[..18].copy_from_slice(KEY_PREFIX);
        bytes[18..34].copy_from_slice(&self.lane);
        bytes[34] = self.owner as u8;
        bytes[35..].copy_from_slice(&self.revision.to_be_bytes());
        bytes
    }

    /// Returns the stable lane correlation identity.
    pub const fn lane(self) -> [u8; 16] {
        self.lane
    }

    /// Returns the independent historical owner.
    pub const fn owner(self) -> OwnerV1 {
        self.owner
    }

    /// Returns zero for a latest head or the exact immutable record revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }
}

/// Supplies immutable envelope coordinates without asserting a native commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordCoordinatesV1 {
    /// The immutable nonzero-revision record key.
    pub key: KeyV1,
    /// The closed state associated with that same key owner.
    pub phase: PhaseV1,
    /// Zero at revision one, otherwise the exact preceding record checksum.
    pub predecessor: [u8; 32],
    /// The stage's seed or validated correlation, checked by its Native owner.
    pub correlation: [u8; 32],
}

impl RecordCoordinatesV1 {
    fn validate(self) -> Result<(), HistoryErrorV1> {
        if self.key.revision == 0
            || self.key.owner != self.phase.owner
            || (self.key.revision == 1) != (self.predecessor == [0; 32])
        {
            return Err(HistoryErrorV1::Correlation);
        }
        nonzero(&self.correlation)
    }
}

/// Borrows a checksum-checked record envelope with an unvalidated phase body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordEnvelopeV1<'a> {
    coordinates: RecordCoordinatesV1,
    body: &'a [u8],
    checksum: [u8; 32],
}

impl<'a> RecordEnvelopeV1<'a> {
    /// Checks the exact envelope, key, closed phase and checksum without allocation.
    ///
    /// Body interpretation is deliberately absent. In particular, a UseReserved
    /// body must later be checked as preappend claim/members/predecessor/forecast
    /// DATA only; its own returned commit result cannot exist inside that record.
    /// Actual returned results first belong in later UseAdmitted/D0 evidence.
    ///
    /// # Errors
    ///
    /// Rejects an unknown format/state, nonzero reserved bytes, zero identities,
    /// key substitution, invalid predecessor shape, nonexact extent or checksum.
    pub fn decode(bytes: &'a [u8], key: KeyV1, phase: PhaseV1) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *RECORD_MAGIC || input.u16()? != 1 {
            return Err(HistoryErrorV1::Malformed);
        }
        let owner = OwnerV1::decode(input.u8()?)?;
        let actual_phase = PhaseV1::new(owner, input.u8()?)?;
        input.zeros(4)?;
        let actual_key = KeyV1::new(input.array()?, owner, input.u64()?)?;
        let coordinates = RecordCoordinatesV1 {
            key: actual_key,
            phase: actual_phase,
            predecessor: input.array()?,
            correlation: input.array()?,
        };
        coordinates.validate()?;
        if coordinates.key != key || coordinates.phase != phase {
            return Err(HistoryErrorV1::Correlation);
        }

        let body_length = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
        let body = input.bytes(body_length)?;
        let checksum = input.array()?;
        input.finish()?;
        let signed_length = RECORD_HEADER_BYTES
            .checked_add(body_length)
            .ok_or(HistoryErrorV1::Extent)?;
        if checksum != record_checksum(&bytes[..signed_length]) {
            return Err(HistoryErrorV1::Checksum);
        }
        Ok(Self { coordinates, body, checksum })
    }

    /// Writes one envelope into an exact caller-owned output slice without allocation.
    ///
    /// The Native caller must validate and price the complete phase body before
    /// providing storage. This operation does not validate nested canonical DATA.
    ///
    /// # Errors
    ///
    /// Rejects invalid coordinates, a body beyond its `u32` wire width, or a
    /// nonexact output length before writing any bytes.
    pub fn encode_into(
        coordinates: RecordCoordinatesV1,
        body: &[u8],
        output: &mut [u8],
    ) -> Result<[u8; 32], HistoryErrorV1> {
        coordinates.validate()?;
        let length = u32::try_from(body.len()).map_err(|_| HistoryErrorV1::Extent)?;
        let total = RECORD_OVERHEAD_BYTES
            .checked_add(body.len())
            .ok_or(HistoryErrorV1::Extent)?;
        if output.len() != total {
            return Err(HistoryErrorV1::Extent);
        }

        output[..8].copy_from_slice(RECORD_MAGIC);
        output[8..10].copy_from_slice(&1_u16.to_be_bytes());
        output[10] = coordinates.key.owner as u8;
        output[11] = coordinates.phase.state;
        output[12..16].fill(0);
        output[16..32].copy_from_slice(&coordinates.key.lane);
        output[32..40].copy_from_slice(&coordinates.key.revision.to_be_bytes());
        output[40..72].copy_from_slice(&coordinates.predecessor);
        output[72..104].copy_from_slice(&coordinates.correlation);
        output[104..108].copy_from_slice(&length.to_be_bytes());
        let body_end = total - 32;
        output[108..body_end].copy_from_slice(body);
        let checksum = record_checksum(&output[..body_end]);
        output[body_end..].copy_from_slice(&checksum);
        Ok(checksum)
    }

    /// Returns original immutable envelope coordinates as passive comparison DATA.
    pub const fn coordinates(self) -> RecordCoordinatesV1 {
        self.coordinates
    }

    /// Borrows the exact phase body without asserting its nested schema.
    pub const fn body(self) -> &'a [u8] {
        self.body
    }

    /// Returns the domain-separated checksum of the complete original record.
    pub const fn checksum(self) -> [u8; 32] {
        self.checksum
    }

    /// Checks exact historical succession without admitting a semantic transition.
    ///
    /// # Errors
    ///
    /// Rejects a changed lane/owner, noncontiguous revision, overflow, or a
    /// predecessor checksum differing from the complete preceding envelope.
    pub fn check_predecessor(self, previous: RecordEnvelopeV1<'_>) -> Result<(), HistoryErrorV1> {
        let old = previous.coordinates.key;
        let new = self.coordinates.key;
        if new.lane != old.lane
            || new.owner != old.owner
            || old.revision.checked_add(1) != Some(new.revision)
            || self.coordinates.predecessor != previous.checksum
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}

/// Holds a fixed latest-head comparison without granting atomic commit authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatestHeadV1 {
    revision: u64,
    checksum: [u8; 32],
}

impl LatestHeadV1 {
    /// Constructs a nonzero revision and exact record checksum as passive DATA.
    ///
    /// # Errors
    ///
    /// Rejects zero revision or checksum.
    pub fn new(revision: u64, checksum: [u8; 32]) -> Result<Self, HistoryErrorV1> {
        if revision == 0 {
            return Err(HistoryErrorV1::Malformed);
        }
        nonzero(&checksum)?;
        Ok(Self { revision, checksum })
    }

    /// Decodes the exact 40-byte head body under a zero-revision head key.
    ///
    /// # Errors
    ///
    /// Rejects a record key, zero fields, truncation or trailing bytes.
    pub fn decode(bytes: &[u8], key: KeyV1) -> Result<Self, HistoryErrorV1> {
        if key.revision != 0 {
            return Err(HistoryErrorV1::Correlation);
        }
        let mut input = reader(bytes);
        let revision = input.u64()?;
        let checksum = input.array()?;
        input.finish()?;
        Self::new(revision, checksum)
    }

    /// Encodes the fixed head body without allocation.
    pub fn encode(self) -> [u8; HEAD_BYTES] {
        let mut bytes = [0; HEAD_BYTES];
        bytes[..8].copy_from_slice(&self.revision.to_be_bytes());
        bytes[8..].copy_from_slice(&self.checksum);
        bytes
    }

    /// Checks the exact record revision/checksum under the supplied head key.
    ///
    /// This comparison does not establish that head and record were atomic.
    ///
    /// # Errors
    ///
    /// Rejects a non-head key or any lane, owner, revision or checksum mismatch.
    pub fn check_record(self, key: KeyV1, record: RecordEnvelopeV1<'_>) -> Result<(), HistoryErrorV1> {
        let record_key = record.coordinates.key;
        if key.revision != 0
            || key.lane != record_key.lane
            || key.owner != record_key.owner
            || self.revision != record_key.revision
            || self.checksum != record.checksum
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}

fn reader(bytes: &[u8]) -> BoundedReader<'_, HistoryErrorV1> {
    BoundedReader::new(bytes, |error| match error {
        ReadError::NonzeroReserved => HistoryErrorV1::Malformed,
        _ => HistoryErrorV1::Extent,
    })
}

fn nonzero<const N: usize>(bytes: &[u8; N]) -> Result<(), HistoryErrorV1> {
    if *bytes == [0; N] {
        return Err(HistoryErrorV1::Malformed);
    }
    Ok(())
}

fn record_checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(RECORD_DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests;
