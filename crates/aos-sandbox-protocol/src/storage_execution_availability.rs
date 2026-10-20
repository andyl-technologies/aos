//! Compares remote Storage execution availability under the shared v2 framing.
//!
//! Both endpoints use the identical compiled AOSHAV02 proposal and accepted
//! AOSNAB02 source. This packet is DATA: the live same-Session continuation,
//! original financial source and actual main/sidecar/NV owners remain held by
//! the native service and its Controller transport lender.
//!
//! ```text
//! AOSSAV02 | phase:u64be | proposal:32 | request:16 | session:32 |
//! signed-request:32 | floor-scope:32 | main-head:32 | main-sequence:u64be |
//! checkpoint-ordinal:u64be | NV:32 | boot:16 | first-clock:u64be |
//! original-cutoff:u64be | observed-clock:u64be | accepted-source:32 | checksum:32
//! ```

use aos_sandbox_core::ProtocolId;
use sha2::{Digest as _, Sha256};

use crate::execution_availability::{ExecutionAvailabilityPhaseV2, ValidatedExecutionAvailabilityRequestV2};
use crate::host_execution_availability::HostExecutionAvailabilityProposalV2;
use crate::host_execution_no_apply::BeforeArgumentNoApplySourceDataV2;
use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError};

/// Exact width of the remote Storage floor observation DATA.
pub const STORAGE_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2: usize = 344;
const MAGIC: &[u8; 8] = b"AOSSAV02";
const DOMAIN: &[u8] = b"aos.sandbox.storage.execution-availability-observation.v2\0";

/// Decodes the common framing and the same canonical Controller proposal.
///
/// # Errors
/// Rejects noncanonical framing, another protocol, a malformed proposal or an
/// accepted source differing from the original compiled request/assignment.
pub fn decode_storage_execution_availability_request_v2(
    body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<ValidatedExecutionAvailabilityRequestV2, ProtocolValidationError> {
    let request = crate::execution_availability::decode_execution_availability_request_v2(
        body, peer, policy, ProtocolId::StorageBroker, now)?;
    let proposal = HostExecutionAvailabilityProposalV2::decode_canonical(request.canonical_proposal())?;
    if request.phase() == ExecutionAvailabilityPhaseV2::AcceptedBind {
        let accepted = BeforeArgumentNoApplySourceDataV2::decode_canonical(request.canonical_accepted_source())
            .map_err(|_| invalid())?;
        proposal.require_accepted_source(accepted)?;
    }
    Ok(request)
}

/// Compares a signed reply to this actual authenticated request's DATA.
///
/// # Errors
/// Rejects a different proposal, request, phase, accepted source, Session or
/// signed request. Native availability must remain independently borrowed.
pub fn validate_storage_execution_availability_response_v2(
    body: &[u8], original: &ValidatedExecutionAvailabilityRequestV2,
    session_binding: [u8; 32], signed_request_digest: [u8; 32],
) -> Result<(), ProtocolValidationError> {
    let bytes = crate::execution_availability::decode_execution_availability_response_v2(body)?;
    let observed = StorageExecutionAvailabilityObservationV2::decode_canonical(&bytes)?.fields();
    let proposal = HostExecutionAvailabilityProposalV2::decode_canonical(original.canonical_proposal())?;
    let accepted = match original.phase() {
        ExecutionAvailabilityPhaseV2::Preaccept => [0; 32],
        ExecutionAvailabilityPhaseV2::AcceptedBind => *BeforeArgumentNoApplySourceDataV2::decode_canonical(
            original.canonical_accepted_source()).map_err(|_| invalid())?.digest().as_bytes(),
    };
    if observed.phase != original.phase() || observed.proposal_digest != *proposal.digest().as_bytes()
        || observed.request != *original.header().request_id() || observed.session != session_binding
        || observed.signed_request != signed_request_digest || observed.bound_source_digest != accepted
        || original.phase() == ExecutionAvailabilityPhaseV2::Preaccept
            && observed.cutoff > original.header().deadline_boottime_nanoseconds()
    { return Err(invalid()); }
    Ok(())
}

/// Carries actual floor coordinates solely for comparison with held owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageExecutionAvailabilityObservationFieldsV2 {
    /// Finite transition completed by the same retained remote receiver.
    pub phase: ExecutionAvailabilityPhaseV2,
    /// Commitment to the original compiled Controller proposal.
    pub proposal_digest: [u8; 32],
    /// Actual current authenticated request identity.
    pub request: [u8; 16],
    /// Original live Controller-to-Storage authenticated Session.
    pub session: [u8; 32],
    /// Digest of the actual signed request carrying this phase.
    pub signed_request: [u8; 32],
    /// Scope of the actual fixed StorageBroker floor provision.
    pub floor_scope: [u8; 32],
    /// Complete namespace-47 HEAD joined to the actual sidecar checkpoint.
    pub main_head: [u8; 32],
    /// Exact main sequence of that same current checkpoint cut.
    pub main_sequence: u64,
    /// Actual canonical checkpoint ordinal retained by the sidecar owner.
    pub checkpoint_ordinal: u64,
    /// Actual authenticated current NV value compared with that checkpoint.
    pub nv_value: [u8; 32],
    /// Actual current Storage service boot.
    pub boot: [u8; 16],
    /// First native paired clock retained by the original preaccept interval.
    pub first_clock: u64,
    /// Original first-D/authorization-clamped cutoff, never renewed by bind.
    ///
    /// A later request's deadline bounds that turn's waits and bookends. It
    /// does not replace this retained scope cutoff; the actual lender must
    /// compare bind responses with the original preaccept clock and cutoff.
    pub cutoff: u64,
    /// Current native clock on the same original provenance/baseline.
    pub observed_clock: u64,
    /// Zero for preaccept; the exact accepted AOSNAB02 commitment for bind.
    pub bound_source_digest: [u8; 32],
}

/// Retains canonical observed DATA without issuing an availability lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageExecutionAvailabilityObservationV2 {
    fields: StorageExecutionAvailabilityObservationFieldsV2,
}

impl StorageExecutionAvailabilityObservationV2 {
    /// Constructs comparison DATA without asserting native or financial origin.
    ///
    /// # Errors
    /// Rejects required zero fields, exhausted sequence/ordinal, backwards or
    /// expired time, or disagreement between phase and accepted-source presence.
    pub fn new(fields: StorageExecutionAvailabilityObservationFieldsV2)
        -> Result<Self, ProtocolValidationError>
    {
        if [fields.proposal_digest, fields.session, fields.signed_request, fields.floor_scope,
            fields.main_head, fields.nv_value].contains(&[0; 32])
            || fields.request == [0; 16] || fields.boot == [0; 16]
            || [0, u64::MAX].contains(&fields.main_sequence)
            || [0, u64::MAX].contains(&fields.checkpoint_ordinal)
            || fields.first_clock == 0 || fields.observed_clock < fields.first_clock
            || fields.observed_clock >= fields.cutoff
            || (fields.phase == ExecutionAvailabilityPhaseV2::Preaccept) != (fields.bound_source_digest == [0; 32])
        { return Err(invalid()); }
        Ok(Self { fields })
    }

    /// Returns the exact comparison coordinates while native custody stays held.
    #[must_use]
    pub const fn fields(self) -> StorageExecutionAvailabilityObservationFieldsV2 { self.fields }

    /// Encodes the sole fixed version of this nonauthorizing observation.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; STORAGE_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2] {
        let mut bytes = [0; STORAGE_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        let phase: u64 = match self.fields.phase {
            ExecutionAvailabilityPhaseV2::Preaccept => 1, ExecutionAvailabilityPhaseV2::AcceptedBind => 2,
        };
        bytes[8..16].copy_from_slice(&phase.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.fields.proposal_digest);
        bytes[48..64].copy_from_slice(&self.fields.request);
        let mut cursor = 64;
        for field in [self.fields.session, self.fields.signed_request, self.fields.floor_scope, self.fields.main_head]
        { bytes[cursor..cursor + 32].copy_from_slice(&field); cursor += 32; }
        bytes[192..200].copy_from_slice(&self.fields.main_sequence.to_be_bytes());
        bytes[200..208].copy_from_slice(&self.fields.checkpoint_ordinal.to_be_bytes());
        bytes[208..240].copy_from_slice(&self.fields.nv_value);
        bytes[240..256].copy_from_slice(&self.fields.boot);
        cursor = 256;
        for field in [self.fields.first_clock, self.fields.cutoff, self.fields.observed_clock]
        { bytes[cursor..cursor + 8].copy_from_slice(&field.to_be_bytes()); cursor += 8; }
        bytes[280..312].copy_from_slice(&self.fields.bound_source_digest);
        let checksum = checksum(&bytes[..312]);
        bytes[312..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes only the exact fixed version and canonical checksum.
    ///
    /// # Errors
    /// Rejects another width/version, malformed coordinates or changed checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != STORAGE_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2
            || bytes.get(..8) != Some(MAGIC.as_slice())
        { return Err(invalid()); }
        let phase = match u64::from_be_bytes(field(bytes, 8)?) {
            1 => ExecutionAvailabilityPhaseV2::Preaccept, 2 => ExecutionAvailabilityPhaseV2::AcceptedBind,
            _ => return Err(invalid()),
        };
        let observation = Self::new(StorageExecutionAvailabilityObservationFieldsV2 {
            phase, proposal_digest: field(bytes, 16)?, request: field(bytes, 48)?, session: field(bytes, 64)?,
            signed_request: field(bytes, 96)?, floor_scope: field(bytes, 128)?, main_head: field(bytes, 160)?,
            main_sequence: u64::from_be_bytes(field(bytes, 192)?),
            checkpoint_ordinal: u64::from_be_bytes(field(bytes, 200)?), nv_value: field(bytes, 208)?,
            boot: field(bytes, 240)?, first_clock: u64::from_be_bytes(field(bytes, 256)?),
            cutoff: u64::from_be_bytes(field(bytes, 264)?), observed_clock: u64::from_be_bytes(field(bytes, 272)?),
            bound_source_digest: field(bytes, 280)?,
        })?;
        if observation.encode_canonical().as_slice() != bytes { return Err(invalid()); }
        Ok(observation)
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes.get(offset..offset.checked_add(N).ok_or_else(invalid)?)
        .and_then(|bytes| bytes.try_into().ok()).ok_or_else(invalid)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(bytes).finalize().into()
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Storage execution availability observation")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> StorageExecutionAvailabilityObservationFieldsV2 {
        StorageExecutionAvailabilityObservationFieldsV2 {
            phase: ExecutionAvailabilityPhaseV2::Preaccept, proposal_digest: [1; 32], request: [2; 16],
            session: [3; 32], signed_request: [4; 32], floor_scope: [5; 32], main_head: [6; 32],
            main_sequence: 7, checkpoint_ordinal: 8, nv_value: [9; 32], boot: [10; 16],
            first_clock: 11, cutoff: 20, observed_clock: 12, bound_source_digest: [0; 32],
        }
    }

    #[test]
    fn every_changed_byte_and_other_width_is_rejected() {
        let original = StorageExecutionAvailabilityObservationV2::new(fields()).unwrap();
        let encoded = original.encode_canonical();
        assert_eq!(StorageExecutionAvailabilityObservationV2::decode_canonical(&encoded).unwrap(), original);
        for index in 0..encoded.len() {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert!(StorageExecutionAvailabilityObservationV2::decode_canonical(&changed).is_err(), "byte {index}");
        }
        assert!(StorageExecutionAvailabilityObservationV2::decode_canonical(&encoded[..343]).is_err());
        assert!(StorageExecutionAvailabilityObservationV2::decode_canonical(&[encoded.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn accepted_bind_and_time_are_not_inferred_from_a_prior_observation() {
        let mut changed = fields();
        changed.phase = ExecutionAvailabilityPhaseV2::AcceptedBind;
        assert!(StorageExecutionAvailabilityObservationV2::new(changed).is_err());
        changed.bound_source_digest = [11; 32];
        assert!(StorageExecutionAvailabilityObservationV2::new(changed).is_ok());
        changed.observed_clock = changed.cutoff;
        assert!(StorageExecutionAvailabilityObservationV2::new(changed).is_err());
        changed.observed_clock = changed.first_clock - 1;
        assert!(StorageExecutionAvailabilityObservationV2::new(changed).is_err());
    }
}
