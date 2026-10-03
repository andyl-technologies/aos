//! Immutable post-issuance custody data for an original public attach ticket.
//!
//! The bounded v2 carrier is not a grant. Host authenticates its exact bytes
//! through the existing signed ATTACH plan; the original AOSAPG01 receipt and
//! certificate retain their original signatures and purposes. Decoding never
//! establishes Controller currentness, authenticated SSH custody, or I/O rights.
//!
//! ```text
//! AOSTKB02 | identities[80] | epoch:u64 | validity[16] | holder[32]
//!         | request[32] | decision[32] | original_grant[416] | route[32]
//!         | certificate_length:u32 | original_certificate | sha256[32]
//! ```

use sha2::{Digest as _, Sha256};

/// Bounds the exact original certificate retained in a v2 ticket carrier.
pub const PUBLIC_ATTACH_TICKET_MAXIMUM_CERTIFICATE_BYTES_V2: usize = 4096;
/// Bounds the complete v2 carrier before parsing or allocation.
pub const PUBLIC_ATTACH_TICKET_MAXIMUM_BYTES_V2: usize = 8192;

const MAGIC: &[u8; 8] = b"AOSTKB02";
const HEADER_BYTES: usize = 8 + 80 + 8 + 16 + 32 + 32 + 32 + 416 + 32 + 4;

/// Retains immutable original ticket bytes without constructing attach authority.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicAttachTicketBindingV2 {
    /// Original accepted attach operation.
    pub operation_id: [u8; 16],
    /// Original execution.
    pub execution_id: [u8; 16],
    /// Original sandbox incarnation.
    pub incarnation_id: [u8; 16],
    /// Original authenticated caller.
    pub principal_id: [u8; 16],
    /// Original execution audit identity.
    pub audit_id: [u8; 16],
    /// Original assignment epoch, not a new assignment authorization.
    pub assignment_epoch: u64,
    /// Inclusive original certificate validity start.
    pub valid_after: u64,
    /// Exclusive original certificate expiry; binding cannot extend it.
    pub expires_at: u64,
    /// Original Ed25519 holder public key.
    pub holder_public_key: [u8; 32],
    /// Commitment to the exact original public request.
    pub request_digest: [u8; 32],
    /// Commitment to Controller's protected original accepted decision.
    pub decision_digest: [u8; 32],
    /// Exact original dedicated-key receipt, unchanged and not re-signed.
    pub pending_grant: [u8; 416],
    /// Original protected Host base route commitment.
    pub base_route_digest: [u8; 32],
    /// Exact original CA-signed certificate bytes, without reconstruction.
    pub certificate: Vec<u8>,
}

impl std::fmt::Debug for PublicAttachTicketBindingV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublicAttachTicketBindingV2(<redacted>)")
    }
}

/// Reports malformed immutable custody data without exposing certificate bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("original attach ticket binding is invalid")]
pub struct PublicAttachTicketBindingErrorV2;

impl PublicAttachTicketBindingV2 {
    /// Encodes the exact original data in the bounded versioned carrier.
    ///
    /// # Errors
    /// Rejects missing identities, invalid validity, an invalid receipt shape,
    /// or empty/oversized certificate bytes. This is only structural validation.
    pub fn encode(&self) -> Result<Vec<u8>, PublicAttachTicketBindingErrorV2> {
        self.validate_shape()?;
        let mut bytes = Vec::with_capacity(HEADER_BYTES + self.certificate.len() + 32);
        bytes.extend_from_slice(MAGIC);
        for identity in [
            self.operation_id,
            self.execution_id,
            self.incarnation_id,
            self.principal_id,
            self.audit_id,
        ] {
            bytes.extend_from_slice(&identity);
        }
        bytes.extend_from_slice(&self.assignment_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.valid_after.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.holder_public_key);
        bytes.extend_from_slice(&self.request_digest);
        bytes.extend_from_slice(&self.decision_digest);
        bytes.extend_from_slice(&self.pending_grant);
        bytes.extend_from_slice(&self.base_route_digest);
        let length =
            u32::try_from(self.certificate.len()).map_err(|_| PublicAttachTicketBindingErrorV2)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.certificate);
        let digest = Sha256::digest(&bytes);
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    /// Decodes canonical data without authenticating its source or signatures.
    ///
    /// # Errors
    /// Rejects unknown versions, truncation, trailing data, invalid bounds or
    /// commitments, and malformed immutable fields before returning a carrier.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicAttachTicketBindingErrorV2> {
        let invalid = PublicAttachTicketBindingErrorV2;
        if bytes.len() < HEADER_BYTES + 32
            || bytes.len() > PUBLIC_ATTACH_TICKET_MAXIMUM_BYTES_V2
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(invalid);
        }
        let mut offset = 8;
        let operation_id = take(bytes, &mut offset)?;
        let execution_id = take(bytes, &mut offset)?;
        let incarnation_id = take(bytes, &mut offset)?;
        let principal_id = take(bytes, &mut offset)?;
        let audit_id = take(bytes, &mut offset)?;
        let assignment_epoch = u64::from_be_bytes(take(bytes, &mut offset)?);
        let valid_after = u64::from_be_bytes(take(bytes, &mut offset)?);
        let expires_at = u64::from_be_bytes(take(bytes, &mut offset)?);
        let holder_public_key = take(bytes, &mut offset)?;
        let request_digest = take(bytes, &mut offset)?;
        let decision_digest = take(bytes, &mut offset)?;
        let pending_grant = take(bytes, &mut offset)?;
        let base_route_digest = take(bytes, &mut offset)?;
        let length = u32::from_be_bytes(take(bytes, &mut offset)?) as usize;
        if length == 0
            || length > PUBLIC_ATTACH_TICKET_MAXIMUM_CERTIFICATE_BYTES_V2
            || bytes.len() != HEADER_BYTES + length + 32
        {
            return Err(invalid);
        }
        let end = HEADER_BYTES + length;
        if Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
            return Err(invalid);
        }
        let value = Self {
            operation_id,
            execution_id,
            incarnation_id,
            principal_id,
            audit_id,
            assignment_epoch,
            valid_after,
            expires_at,
            holder_public_key,
            request_digest,
            decision_digest,
            pending_grant,
            base_route_digest,
            certificate: bytes[offset..end].to_vec(),
        };
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), PublicAttachTicketBindingErrorV2> {
        if [
            self.operation_id,
            self.execution_id,
            self.incarnation_id,
            self.principal_id,
            self.audit_id,
        ]
        .iter()
        .any(|identity| identity == &[0; 16])
            || self.assignment_epoch == 0
            || self.valid_after == 0
            || self.expires_at <= self.valid_after
            || self.expires_at - self.valid_after
                > u64::from(
                    super::public_attach_route::PUBLIC_ATTACH_CERTIFICATE_MAXIMUM_SECONDS_V1,
                )
            || [
                self.holder_public_key,
                self.request_digest,
                self.decision_digest,
                self.base_route_digest,
            ]
            .iter()
            .any(|digest| digest == &[0; 32])
            || self.pending_grant.get(..8) != Some(b"AOSAPG01".as_slice())
            || self.pending_grant.get(8..24) != Some(self.operation_id.as_slice())
            || self.pending_grant.get(24..40) != Some(self.execution_id.as_slice())
            || self.certificate.is_empty()
            || self.certificate.len() > PUBLIC_ATTACH_TICKET_MAXIMUM_CERTIFICATE_BYTES_V2
        {
            return Err(PublicAttachTicketBindingErrorV2);
        }
        Ok(())
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], PublicAttachTicketBindingErrorV2> {
    let end = offset
        .checked_add(N)
        .ok_or(PublicAttachTicketBindingErrorV2)?;
    let value = bytes
        .get(*offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(PublicAttachTicketBindingErrorV2)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_bytes_round_trip_and_hostile_records_fail_closed() {
        let mut grant = [0; 416];
        grant[..8].copy_from_slice(b"AOSAPG01");
        grant[8..24].copy_from_slice(&[1; 16]);
        grant[24..40].copy_from_slice(&[2; 16]);
        let ticket = PublicAttachTicketBindingV2 {
            operation_id: [1; 16],
            execution_id: [2; 16],
            incarnation_id: [3; 16],
            principal_id: [4; 16],
            audit_id: [5; 16],
            assignment_epoch: 1,
            valid_after: 100,
            expires_at: 200,
            holder_public_key: [6; 32],
            request_digest: [7; 32],
            decision_digest: [8; 32],
            pending_grant: grant,
            base_route_digest: [9; 32],
            certificate: b"original-certificate".to_vec(),
        };
        let bytes = ticket.encode().unwrap();
        assert_eq!(PublicAttachTicketBindingV2::decode(&bytes).unwrap(), ticket);
        for length in 0..bytes.len() {
            assert!(PublicAttachTicketBindingV2::decode(&bytes[..length]).is_err());
        }
        let mut altered = bytes.clone();
        altered[HEADER_BYTES] ^= 1;
        assert!(PublicAttachTicketBindingV2::decode(&altered).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PublicAttachTicketBindingV2::decode(&trailing).is_err());
        let mut substituted = ticket;
        substituted.operation_id = [10; 16];
        assert!(substituted.encode().is_err());
    }
}
