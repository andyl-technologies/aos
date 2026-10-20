//! Compares predurable Host availability without creating a native loan.
//!
//! The proposal contains the compiled public request and protected assignment
//! before a Create identity exists. Its accepted continuation uses the actual
//! AOSNAB02 source. Neither canonical DATA nor a signed historical response can
//! replace the Session, paid native receiver, four writers, or HostState owner.
//!
//! ```text
//! AOSHAV02 | sandbox:16 | incarnation:16 | node:16 | epoch:u64be |
//! generation:u64be | public-request:32 | assignment:32 | nonce:16 | checksum:32
//! ```

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::ProtocolValidationError;
use crate::host_execution_no_apply::BeforeArgumentNoApplySourceDataV2;

pub mod observation;

use crate::execution_availability::{
    ExecutionAvailabilityPhaseV2, ValidatedExecutionAvailabilityRequestV2,
};

/// Decodes Host availability framing and both exact canonical payloads.
///
/// # Errors
/// Rejects invalid framing/proposal or an accepted source differing from the
/// original compiled request and assignment. This proves no native custody.
pub fn decode_host_execution_availability_request_v2(
    body: &[u8],
    peer: crate::PeerCredentials,
    policy: crate::PeerPolicy,
    now: u64,
) -> Result<ValidatedExecutionAvailabilityRequestV2, ProtocolValidationError> {
    let request = crate::execution_availability::decode_execution_availability_request_v2(
        body,
        peer,
        policy,
        aos_sandbox_core::ProtocolId::HostBroker,
        now,
    )?;
    let proposal =
        HostExecutionAvailabilityProposalV2::decode_canonical(request.canonical_proposal())?;
    if request.phase() == ExecutionAvailabilityPhaseV2::AcceptedBind {
        let source = BeforeArgumentNoApplySourceDataV2::decode_canonical(
            request.canonical_accepted_source(),
        )
        .map_err(|_| invalid())?;
        proposal.require_accepted_source(source)?;
    }
    Ok(request)
}

/// Compares the signed reply to this actual authenticated request's DATA.
///
/// # Errors
/// Rejects a different proposal, phase, accepted source, Session or signed
/// request. Actual retained native ownership must be checked separately.
pub fn validate_host_execution_availability_response_v2(
    body: &[u8],
    original: &ValidatedExecutionAvailabilityRequestV2,
    session_binding: [u8; 32],
    signed_request_digest: [u8; 32],
) -> Result<(), ProtocolValidationError> {
    let bytes = crate::execution_availability::decode_execution_availability_response_v2(body)?;
    let observed =
        observation::HostExecutionAvailabilityObservationV2::decode_canonical(&bytes)?.fields();
    let proposal =
        HostExecutionAvailabilityProposalV2::decode_canonical(original.canonical_proposal())?;
    let bound_source_digest = match original.phase() {
        ExecutionAvailabilityPhaseV2::Preaccept => [0; 32],
        ExecutionAvailabilityPhaseV2::AcceptedBind => {
            *BeforeArgumentNoApplySourceDataV2::decode_canonical(
                original.canonical_accepted_source(),
            )
            .map_err(|_| invalid())?
            .digest()
            .as_bytes()
        }
    };
    if observed.proposal_digest != *proposal.digest().as_bytes()
        || observed.phase != original.phase()
        || observed.request != *original.header().request_id()
        || observed.session != session_binding
        || observed.signed_request != signed_request_digest
        || observed.bound_source_digest != bound_source_digest
        || observed.observed_clock >= original.header().deadline_boottime_nanoseconds()
        || original.phase() == ExecutionAvailabilityPhaseV2::Preaccept
            && observed.cutoff > original.header().deadline_boottime_nanoseconds()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Exact width of a predurable proposal, with no manufactured Create identity.
pub const HOST_EXECUTION_AVAILABILITY_PROPOSAL_BYTES_V2: usize = 184;

const MAGIC: &[u8; 8] = b"AOSHAV02";
const DOMAIN: &[u8] = b"aos.sandbox.host.execution-availability-proposal.v2\0";

/// Carries compiled request and protected assignment coordinates as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionAvailabilityProposalFieldsV2 {
    /// Sandbox read from the retained current Controller assignment.
    pub sandbox: [u8; 16],
    /// Incarnation read from that same assignment.
    pub incarnation: [u8; 16],
    /// Host node read from that same assignment.
    pub node: [u8; 16],
    /// Current protected assignment epoch.
    pub assignment_epoch: u64,
    /// Current desired-state generation.
    pub desired_generation: u64,
    /// Exact request digest produced by the retained canonical public compiler.
    pub public_request_digest: [u8; 32],
    /// Exact current protected assignment manifest digest.
    pub assignment_digest: [u8; 32],
    /// One fresh challenge chosen by the actual original caller.
    pub nonce: [u8; 16],
}

/// Retains structurally canonical proposal DATA without authenticating custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionAvailabilityProposalV2 {
    fields: HostExecutionAvailabilityProposalFieldsV2,
}

impl HostExecutionAvailabilityProposalV2 {
    /// Constructs comparison DATA from independently supplied coordinates.
    ///
    /// # Errors
    /// Rejects zero identities, generation, epoch, nonce or commitments.
    pub fn new(
        fields: HostExecutionAvailabilityProposalFieldsV2,
    ) -> Result<Self, ProtocolValidationError> {
        if [
            fields.sandbox,
            fields.incarnation,
            fields.node,
            fields.nonce,
        ]
        .contains(&[0; 16])
            || fields.assignment_epoch == 0
            || fields.desired_generation == 0
            || [fields.public_request_digest, fields.assignment_digest].contains(&[0; 32])
        {
            return Err(invalid());
        }
        Ok(Self { fields })
    }

    /// Returns the original proposal coordinates as comparison DATA.
    #[must_use]
    pub const fn fields(self) -> HostExecutionAvailabilityProposalFieldsV2 {
        self.fields
    }

    /// Encodes the exact proposal independently of transport framing.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; HOST_EXECUTION_AVAILABILITY_PROPOSAL_BYTES_V2] {
        let mut bytes = [0; HOST_EXECUTION_AVAILABILITY_PROPOSAL_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.fields.sandbox);
        bytes[24..40].copy_from_slice(&self.fields.incarnation);
        bytes[40..56].copy_from_slice(&self.fields.node);
        bytes[56..64].copy_from_slice(&self.fields.assignment_epoch.to_be_bytes());
        bytes[64..72].copy_from_slice(&self.fields.desired_generation.to_be_bytes());
        bytes[72..104].copy_from_slice(&self.fields.public_request_digest);
        bytes[104..136].copy_from_slice(&self.fields.assignment_digest);
        bytes[136..152].copy_from_slice(&self.fields.nonce);
        let checksum = checksum(&bytes[..152]);
        bytes[152..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes only the exact proposal version and canonical checksum.
    ///
    /// # Errors
    /// Rejects another version, wrong width, zero fields or changed checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_EXECUTION_AVAILABILITY_PROPOSAL_BYTES_V2
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(invalid());
        }
        let proposal = Self::new(HostExecutionAvailabilityProposalFieldsV2 {
            sandbox: field(bytes, 8)?,
            incarnation: field(bytes, 24)?,
            node: field(bytes, 40)?,
            assignment_epoch: u64::from_be_bytes(field(bytes, 56)?),
            desired_generation: u64::from_be_bytes(field(bytes, 64)?),
            public_request_digest: field(bytes, 72)?,
            assignment_digest: field(bytes, 104)?,
            nonce: field(bytes, 136)?,
        })?;
        if proposal.encode_canonical().as_slice() != bytes {
            return Err(invalid());
        }
        Ok(proposal)
    }

    /// Returns the domain-separated proposal commitment as DATA.
    #[must_use]
    pub fn digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(checksum(&self.encode_canonical()[..152]))
    }

    /// Compares a later actual accepted Create with this original proposal.
    ///
    /// This authenticates neither acceptance nor the Host boot. Those checks
    /// belong to the same retained Controller and Host native owners.
    ///
    /// # Errors
    /// Rejects any changed compiled request or protected assignment coordinate.
    pub fn require_accepted_source(
        self,
        accepted: BeforeArgumentNoApplySourceDataV2,
    ) -> Result<(), ProtocolValidationError> {
        let accepted = accepted.fields();
        let original = self.fields;
        if accepted.sandbox != original.sandbox
            || accepted.incarnation != original.incarnation
            || accepted.node != original.node
            || accepted.assignment_epoch != original.assignment_epoch
            || accepted.desired_generation != original.desired_generation
            || accepted.accepted_request_digest != original.public_request_digest
            || accepted.assignment_digest != original.assignment_digest
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn field<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes
        .get(start..start.checked_add(N).ok_or_else(invalid)?)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(invalid)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host execution availability proposal")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_execution_no_apply::BeforeArgumentNoApplySourceFieldsV2;

    fn proposal() -> HostExecutionAvailabilityProposalV2 {
        HostExecutionAvailabilityProposalV2::new(HostExecutionAvailabilityProposalFieldsV2 {
            sandbox: [1; 16],
            incarnation: [2; 16],
            node: [3; 16],
            assignment_epoch: 4,
            desired_generation: 5,
            public_request_digest: [6; 32],
            assignment_digest: [7; 32],
            nonce: [8; 16],
        })
        .unwrap()
    }

    fn accepted() -> BeforeArgumentNoApplySourceFieldsV2 {
        BeforeArgumentNoApplySourceFieldsV2 {
            create_operation: [9; 16],
            execution: [10; 16],
            sandbox: [1; 16],
            incarnation: [2; 16],
            node: [3; 16],
            host_boot: [11; 16],
            assignment_epoch: 4,
            desired_generation: 5,
            accepted_request_digest: [6; 32],
            assignment_digest: [7; 32],
        }
    }

    #[test]
    fn accepted_create_may_add_only_actual_postacceptance_identities() {
        let proposal = proposal();
        assert!(
            proposal
                .require_accepted_source(
                    BeforeArgumentNoApplySourceDataV2::new(accepted()).unwrap()
                )
                .is_ok()
        );
        for changed in 0..7 {
            let mut fields = accepted();
            match changed {
                0 => fields.sandbox[0] ^= 1,
                1 => fields.incarnation[0] ^= 1,
                2 => fields.node[0] ^= 1,
                3 => fields.assignment_epoch += 1,
                4 => fields.desired_generation += 1,
                5 => fields.accepted_request_digest[0] ^= 1,
                _ => fields.assignment_digest[0] ^= 1,
            }
            assert!(
                proposal
                    .require_accepted_source(
                        BeforeArgumentNoApplySourceDataV2::new(fields).unwrap()
                    )
                    .is_err(),
                "changed field {changed}"
            );
        }
    }

    #[test]
    fn proposal_rejects_every_changed_byte_and_other_widths() {
        let encoded = proposal().encode_canonical();
        assert_eq!(
            HostExecutionAvailabilityProposalV2::decode_canonical(&encoded).unwrap(),
            proposal()
        );
        for index in 0..encoded.len() {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert!(
                HostExecutionAvailabilityProposalV2::decode_canonical(&changed).is_err(),
                "byte {index}"
            );
        }
        assert!(HostExecutionAvailabilityProposalV2::decode_canonical(&encoded[..183]).is_err());
        assert!(
            HostExecutionAvailabilityProposalV2::decode_canonical(
                &[encoded.as_slice(), &[0]].concat()
            )
            .is_err()
        );
    }
}
