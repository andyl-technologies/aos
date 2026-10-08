//! Converts committed local lease artifacts for explicitly selected coordinators.
//!
//! Conversion retains the canonical lease and signatures. It issues no lease
//! and never replaces the local protected issuer or its recovery authority.

use aos_proto::aos::sandbox::coordinator::v1 as wire;
use aos_sandbox_core::DecodeLimits;
use aos_sandbox_core::format::decode_ownership_lease;

use crate::local_ownership::ProtectedCommittedLeaseV1;

impl ProtectedCommittedLeaseV1 {
    /// Returns the coordinator protobuf representation of the committed lease.
    ///
    /// # Errors
    ///
    /// Returns [`super::super::InvalidMultiNodeProtocol::NonCanonicalFrame`] if the
    /// protected canonical lease cannot be decoded exactly. This indicates
    /// corruption because the local authority verifies the lease before commit.
    pub fn protobuf(&self) -> Result<wire::AssignmentLease, super::super::InvalidMultiNodeProtocol> {
        let lease = decode_ownership_lease(
            self.lease(),
            DecodeLimits {
                maximum_bytes: self.lease().len(),
                ..DecodeLimits::default()
            },
        )
        .map_err(|_| super::super::InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let assignment = lease.assignment();

        Ok(wire::AssignmentLease {
            sandbox_uid: assignment.sandbox().as_bytes().to_vec(),
            incarnation_uid: assignment.incarnation().as_bytes().to_vec(),
            assignment_epoch: assignment.epoch().get(),
            assignment_sha256: assignment.digest().as_bytes().to_vec(),
            node_uid: lease.node().as_bytes().to_vec(),
            generation: lease.lease_generation(),
            issued_at_unix_seconds: lease.authority_issued_seconds(),
            expires_at_unix_seconds: lease.authority_expires_seconds(),
            maximum_clock_skew_seconds: lease.maximum_clock_skew_seconds(),
            renewal_nonce: lease.renewal_nonce().to_vec(),
            canonical_lease: self.lease().to_vec(),
            canonical_signature: self.signature().to_vec(),
            canonical_receipt: self.receipt().to_vec(),
            canonical_receipt_signature: self.receipt_signature().to_vec(),
            ..Default::default()
        })
    }
}
