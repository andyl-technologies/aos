//! Canonical codec for ownership-authority-signed assignment leases.

use crate::ownership_lease::{LeaseAssignment, OwnershipLease};
use crate::{AssignmentEpoch, IncarnationId, NodeId, ObjectDigest, SandboxId};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{exact_bytes, semantics};

/// Encodes an ownership lease in exact portable v1 CBOR.
#[must_use]
pub fn encode_ownership_lease(lease: &OwnershipLease) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(8);
    encoder.unsigned(1);
    encode_assignment(&mut encoder, lease.assignment());
    encoder.bytes(lease.node().as_bytes());
    encoder.unsigned(lease.lease_generation());
    encoder.signed(lease.authority_issued_seconds());
    encoder.signed(lease.authority_expires_seconds());
    encoder.unsigned(lease.maximum_clock_skew_seconds());
    encoder.bytes(lease.renewal_nonce());
    encoder.finish()
}

/// Decodes one exact canonical ownership lease.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for deterministic-CBOR violations, invalid
/// bounds, or reserved identity values.
pub fn decode_ownership_lease(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<OwnershipLease, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(8)?;
    decoder.exact("ownership lease version", 1)?;
    let assignment = decode_assignment(&mut decoder)?;
    let node = NodeId::from_bytes(exact_bytes::<16>(&mut decoder, 16)?);
    let generation = decoder.unsigned()?;
    let issued = decoder.signed()?;
    let expires = decoder.signed()?;
    let maximum_skew = decoder.unsigned()?;
    let renewal_nonce = exact_bytes::<16>(&mut decoder, 16)?;
    decoder.finish()?;

    OwnershipLease::new(
        assignment,
        node,
        generation,
        issued,
        expires,
        maximum_skew,
        renewal_nonce,
    )
    .map_err(|error| semantics("ownership lease", error))
}

fn encode_assignment(encoder: &mut Encoder, assignment: LeaseAssignment) {
    encoder.array(4);
    encoder.bytes(assignment.sandbox().as_bytes());
    encoder.bytes(assignment.incarnation().as_bytes());
    encoder.unsigned(assignment.epoch().get());
    encoder.bytes(assignment.digest().as_bytes());
}

fn decode_assignment(decoder: &mut Decoder<'_>) -> Result<LeaseAssignment, CanonicalCborError> {
    decoder.array(4)?;
    LeaseAssignment::new(
        SandboxId::from_bytes(exact_bytes::<16>(decoder, 16)?),
        IncarnationId::from_bytes(exact_bytes::<16>(decoder, 16)?),
        AssignmentEpoch::new(decoder.unsigned()?),
        ObjectDigest::from_bytes(exact_bytes::<32>(decoder, 32)?),
    )
    .map_err(|error| semantics("ownership lease assignment", error))
}
