//! Encodes current Host availability coordinates solely as comparison DATA.
//!
//! ```text
//! AOSHAC02 | phase:u64be | proposal:32 | request:16 | session:32 |
//! signed-request:32 | runtime:32 | execution-store:32 | execution-cut:32 |
//! HostState-cut:32 | boot:16 | epoch:u64be | first-clock:u64be |
//! original-cutoff:u64be | observed-clock:u64be | accepted-source:32 | checksum:32
//! ```

use super::{field, invalid};
use crate::ProtocolValidationError;
use crate::execution_availability::ExecutionAvailabilityPhaseV2;
use sha2::{Digest as _, Sha256};

/// Exact width of a current nonauthorizing Host availability observation.
pub const HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2: usize = 368;
const MAGIC: &[u8; 8] = b"AOSHAC02";
const DOMAIN: &[u8] = b"aos.sandbox.host.execution-availability-observation.v2\0";

/// Lists actual owner coordinates to compare with independently read state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionAvailabilityObservationFieldsV2 {
    /// Finite transition completed by the actual retained receiver.
    pub phase: ExecutionAvailabilityPhaseV2,
    /// Original compiled proposal commitment.
    pub proposal_digest: [u8; 32],
    /// Actual authenticated current request identity.
    pub request: [u8; 16],
    /// Actual original authenticated Controller Session.
    pub session: [u8; 32],
    /// Actual signed current request digest.
    pub signed_request: [u8; 32],
    /// Current protected runtime identity.
    pub runtime_handle: [u8; 32],
    /// Current protected execution journal identity.
    pub execution_store: [u8; 32],
    /// Actual protected execution cut held by the same writer.
    pub execution_cut: [u8; 32],
    /// Actual HostState cut held by the same exclusive store.
    pub host_state_cut: [u8; 32],
    /// Native current Host boot.
    pub boot: [u8; 16],
    /// Actual protected execution epoch.
    pub epoch: u64,
    /// First paired native clock from the original preaccept interval.
    pub first_clock: u64,
    /// Original clamped cutoff, never renewed by later headers or queries.
    pub cutoff: u64,
    /// Current paired native clock on that same original baseline.
    pub observed_clock: u64,
    /// Zero before acceptance; exact AOSNAB02 commitment after binding.
    pub bound_source_digest: [u8; 32],
}

/// Retains canonical observed DATA without constructing a receiver or lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionAvailabilityObservationV2 {
    fields: HostExecutionAvailabilityObservationFieldsV2,
}

impl HostExecutionAvailabilityObservationV2 {
    /// Constructs comparison DATA from actual or independently supplied fields.
    ///
    /// # Errors
    /// Rejects zero required identities, a renewed/expired clock interval, or
    /// disagreement between the phase and accepted-source presence.
    pub fn new(
        fields: HostExecutionAvailabilityObservationFieldsV2,
    ) -> Result<Self, ProtocolValidationError> {
        if [
            fields.proposal_digest,
            fields.session,
            fields.signed_request,
            fields.runtime_handle,
            fields.execution_store,
            fields.execution_cut,
            fields.host_state_cut,
        ]
        .contains(&[0; 32])
            || fields.request == [0; 16]
            || fields.boot == [0; 16]
            || fields.epoch == 0
            || fields.first_clock == 0
            || fields.observed_clock < fields.first_clock
            || fields.observed_clock >= fields.cutoff
            || (fields.phase == ExecutionAvailabilityPhaseV2::Preaccept)
                != (fields.bound_source_digest == [0; 32])
        {
            return Err(invalid());
        }
        Ok(Self { fields })
    }

    /// Returns observed coordinates for comparison while native custody stays held.
    #[must_use]
    pub const fn fields(self) -> HostExecutionAvailabilityObservationFieldsV2 {
        self.fields
    }

    /// Encodes the exact current-observation grammar.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2] {
        let mut bytes = [0; HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        let phase: u64 = match self.fields.phase {
            ExecutionAvailabilityPhaseV2::Preaccept => 1,
            ExecutionAvailabilityPhaseV2::AcceptedBind => 2,
        };
        bytes[8..16].copy_from_slice(&phase.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.fields.proposal_digest);
        bytes[48..64].copy_from_slice(&self.fields.request);
        let mut cursor = 64;
        for field in [
            self.fields.session,
            self.fields.signed_request,
            self.fields.runtime_handle,
            self.fields.execution_store,
            self.fields.execution_cut,
            self.fields.host_state_cut,
        ] {
            bytes[cursor..cursor + 32].copy_from_slice(&field);
            cursor += 32;
        }
        bytes[256..272].copy_from_slice(&self.fields.boot);
        cursor = 272;
        for field in [
            self.fields.epoch,
            self.fields.first_clock,
            self.fields.cutoff,
            self.fields.observed_clock,
        ] {
            bytes[cursor..cursor + 8].copy_from_slice(&field.to_be_bytes());
            cursor += 8;
        }
        bytes[304..336].copy_from_slice(&self.fields.bound_source_digest);
        let checksum = checksum(&bytes[..336]);
        bytes[336..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes only the exact current-observation grammar.
    ///
    /// # Errors
    /// Rejects another version, wrong width, invalid bindings or changed checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(invalid());
        }
        let phase = match u64::from_be_bytes(field(bytes, 8)?) {
            1 => ExecutionAvailabilityPhaseV2::Preaccept,
            2 => ExecutionAvailabilityPhaseV2::AcceptedBind,
            _ => return Err(invalid()),
        };
        let observation = Self::new(HostExecutionAvailabilityObservationFieldsV2 {
            phase,
            proposal_digest: field(bytes, 16)?,
            request: field(bytes, 48)?,
            session: field(bytes, 64)?,
            signed_request: field(bytes, 96)?,
            runtime_handle: field(bytes, 128)?,
            execution_store: field(bytes, 160)?,
            execution_cut: field(bytes, 192)?,
            host_state_cut: field(bytes, 224)?,
            boot: field(bytes, 256)?,
            epoch: u64::from_be_bytes(field(bytes, 272)?),
            first_clock: u64::from_be_bytes(field(bytes, 280)?),
            cutoff: u64::from_be_bytes(field(bytes, 288)?),
            observed_clock: u64::from_be_bytes(field(bytes, 296)?),
            bound_source_digest: field(bytes, 304)?,
        })?;
        if observation.encode_canonical().as_slice() != bytes {
            return Err(invalid());
        }
        Ok(observation)
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}
