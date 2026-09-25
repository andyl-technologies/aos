//! Canonical Host no-Apply terminal marker shared by wire and protected owner.
//!
//! The marker is historical Host custody, not Controller failure settlement or
//! authority to issue another Guest observation. Its fixed bytes are:
//!
//! ```text
//! AOSHNA01 || execution:16 || Create-operation:16
//!          || original-request:16 || terminal-request:16 || Host-boot:16
//!          || assignment:32 || AOSCIA02-record:32
//!          || original-session:32 || original-signed-request:32
//!          || terminal-session:32 || terminal-signed-request:32
//!          || runtime-handle:32 || execution-store-binding:32
//!          || commit-sequence:u64be
//!          || SHA256("aos.sandbox.host.no-apply-record.v1\0" || preceding):32
//! ```

use sha2::{Digest as _, Sha256};

mod transport;

#[cfg(test)]
pub(crate) use transport::tests as test_support;
pub use transport::{
    HostExecutionNoApplyReadbackV1, ValidatedHostExecutionNoApplyRequestV1,
    decode_host_execution_argument_no_apply_request_v1,
    decode_host_execution_argument_no_apply_response_v1,
    decode_host_execution_argument_query_no_apply_request_v1,
    decode_host_execution_argument_query_no_apply_response_v1,
};

const MAGIC: &[u8; 8] = b"AOSHNA01";
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.host.no-apply-record.v1\0";

/// Exact byte count of a canonical Host no-Apply marker.
pub const HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1: usize = 384;

/// Reports a malformed or noncanonical Host terminal marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostExecutionNoApplyRecordErrorV1 {
    /// The marker has an unknown version, zero identity, or invalid checksum.
    #[error("Host no-Apply record is not canonical")]
    InvalidRecord,
}

/// Names every exact identity retained by a Host no-Apply marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionNoApplyRecordFieldsV1 {
    /// Accepted execution ID.
    pub execution_id: [u8; 16],
    /// Accepted Create operation ID.
    pub create_operation_id: [u8; 16],
    /// Original method-37 request ID.
    pub original_request_id: [u8; 16],
    /// Mutating method-39 request ID.
    pub terminal_request_id: [u8; 16],
    /// Original Host kernel boot ID.
    pub host_boot_id: [u8; 16],
    /// Assignment manifest commitment.
    pub assignment_digest: [u8; 32],
    /// Exact AOSCIA02 source-record digest.
    pub source_record_digest: [u8; 32],
    /// Original method-37 authenticated session binding.
    pub original_session_binding: [u8; 32],
    /// Signed original method-37 ClientRecord digest.
    pub original_signed_request_digest: [u8; 32],
    /// Mutating method-39 authenticated session binding.
    pub terminal_session_binding: [u8; 32],
    /// Signed method-39 ClientRecord digest.
    pub terminal_signed_request_digest: [u8; 32],
    /// Protected Host runtime handle.
    pub runtime_handle: [u8; 32],
    /// Sealed execution-store binding.
    pub execution_store_binding: [u8; 32],
    /// Sequence assigned by the protected execution journal.
    pub commit_sequence: u64,
}

impl HostExecutionNoApplyRecordFieldsV1 {
    fn valid(self) -> bool {
        [
            self.execution_id,
            self.create_operation_id,
            self.original_request_id,
            self.terminal_request_id,
            self.host_boot_id,
        ]
        .iter()
        .all(|field| *field != [0; 16])
            && [
                self.assignment_digest,
                self.source_record_digest,
                self.original_session_binding,
                self.original_signed_request_digest,
                self.terminal_session_binding,
                self.terminal_signed_request_digest,
                self.runtime_handle,
                self.execution_store_binding,
            ]
            .iter()
            .all(|field| *field != [0; 32])
            && self.original_request_id != self.terminal_request_id
            && self.commit_sequence != 0
    }
}

/// Retains one structurally canonical, nonauthorizing Host no-Apply record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionNoApplyRecordV1 {
    fields: HostExecutionNoApplyRecordFieldsV1,
}

impl HostExecutionNoApplyRecordV1 {
    /// Constructs a canonical marker after the Host owner commits its sequence.
    ///
    /// # Errors
    ///
    /// Rejects a zero identity or sequence, or reuse of the original request ID.
    pub fn new(
        fields: HostExecutionNoApplyRecordFieldsV1,
    ) -> Result<Self, HostExecutionNoApplyRecordErrorV1> {
        if !fields.valid() {
            return Err(HostExecutionNoApplyRecordErrorV1::InvalidRecord);
        }
        Ok(Self { fields })
    }

    /// Returns the exact immutable fields for owner and response comparisons.
    #[must_use]
    pub const fn fields(self) -> HostExecutionNoApplyRecordFieldsV1 {
        self.fields
    }

    /// Encodes the exact fixed-length marker and structural checksum.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1] {
        let fields = self.fields;
        let mut bytes = [0; HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&fields.execution_id);
        bytes[24..40].copy_from_slice(&fields.create_operation_id);
        bytes[40..56].copy_from_slice(&fields.original_request_id);
        bytes[56..72].copy_from_slice(&fields.terminal_request_id);
        bytes[72..88].copy_from_slice(&fields.host_boot_id);
        bytes[88..120].copy_from_slice(&fields.assignment_digest);
        bytes[120..152].copy_from_slice(&fields.source_record_digest);
        bytes[152..184].copy_from_slice(&fields.original_session_binding);
        bytes[184..216].copy_from_slice(&fields.original_signed_request_digest);
        bytes[216..248].copy_from_slice(&fields.terminal_session_binding);
        bytes[248..280].copy_from_slice(&fields.terminal_signed_request_digest);
        bytes[280..312].copy_from_slice(&fields.runtime_handle);
        bytes[312..344].copy_from_slice(&fields.execution_store_binding);
        bytes[344..352].copy_from_slice(&fields.commit_sequence.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(DIGEST_DOMAIN)
            .chain_update(&bytes[..352])
            .finalize();
        bytes[352..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes only an exact, checksummed canonical marker.
    ///
    /// # Errors
    ///
    /// Rejects truncation, trailing bytes, unknown versions, zero fields,
    /// request-ID reuse, or checksum changes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, HostExecutionNoApplyRecordErrorV1> {
        if bytes.len() != HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(HostExecutionNoApplyRecordErrorV1::InvalidRecord);
        }
        let mut cursor = 8;
        let fields = HostExecutionNoApplyRecordFieldsV1 {
            execution_id: take(bytes, &mut cursor)?,
            create_operation_id: take(bytes, &mut cursor)?,
            original_request_id: take(bytes, &mut cursor)?,
            terminal_request_id: take(bytes, &mut cursor)?,
            host_boot_id: take(bytes, &mut cursor)?,
            assignment_digest: take(bytes, &mut cursor)?,
            source_record_digest: take(bytes, &mut cursor)?,
            original_session_binding: take(bytes, &mut cursor)?,
            original_signed_request_digest: take(bytes, &mut cursor)?,
            terminal_session_binding: take(bytes, &mut cursor)?,
            terminal_signed_request_digest: take(bytes, &mut cursor)?,
            runtime_handle: take(bytes, &mut cursor)?,
            execution_store_binding: take(bytes, &mut cursor)?,
            commit_sequence: u64::from_be_bytes(take(bytes, &mut cursor)?),
        };
        let record = Self::new(fields)?;
        if record.encode_canonical().as_slice() != bytes {
            return Err(HostExecutionNoApplyRecordErrorV1::InvalidRecord);
        }
        Ok(record)
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], HostExecutionNoApplyRecordErrorV1> {
    let end = cursor
        .checked_add(N)
        .ok_or(HostExecutionNoApplyRecordErrorV1::InvalidRecord)?;
    let field = bytes
        .get(*cursor..end)
        .ok_or(HostExecutionNoApplyRecordErrorV1::InvalidRecord)?;
    *cursor = end;
    field
        .try_into()
        .map_err(|_| HostExecutionNoApplyRecordErrorV1::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> HostExecutionNoApplyRecordFieldsV1 {
        HostExecutionNoApplyRecordFieldsV1 {
            execution_id: [1; 16],
            create_operation_id: [2; 16],
            original_request_id: [3; 16],
            terminal_request_id: [4; 16],
            host_boot_id: [5; 16],
            assignment_digest: [6; 32],
            source_record_digest: [7; 32],
            original_session_binding: [8; 32],
            original_signed_request_digest: [9; 32],
            terminal_session_binding: [10; 32],
            terminal_signed_request_digest: [11; 32],
            runtime_handle: [12; 32],
            execution_store_binding: [13; 32],
            commit_sequence: 14,
        }
    }

    #[test]
    fn no_apply_record_is_exact_and_checks_every_byte() {
        let record = HostExecutionNoApplyRecordV1::new(fields()).unwrap();
        let bytes = record.encode_canonical();
        assert_eq!(bytes.len(), HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1);
        assert_eq!(
            HostExecutionNoApplyRecordV1::decode_canonical(&bytes),
            Ok(record)
        );

        for index in 0..bytes.len() {
            let mut tampered = bytes;
            tampered[index] ^= 1;
            assert!(HostExecutionNoApplyRecordV1::decode_canonical(&tampered).is_err());
        }
        assert!(HostExecutionNoApplyRecordV1::decode_canonical(&bytes[..383]).is_err());
        assert!(
            HostExecutionNoApplyRecordV1::decode_canonical(&[bytes.as_slice(), &[0]].concat())
                .is_err()
        );
    }

    #[test]
    fn no_apply_record_rejects_zero_and_reused_request_identity() {
        let mut invalid = fields();
        invalid.original_request_id = invalid.terminal_request_id;
        assert!(HostExecutionNoApplyRecordV1::new(invalid).is_err());
        invalid = fields();
        invalid.execution_store_binding = [0; 32];
        assert!(HostExecutionNoApplyRecordV1::new(invalid).is_err());
        invalid = fields();
        invalid.commit_sequence = 0;
        assert!(HostExecutionNoApplyRecordV1::new(invalid).is_err());
    }
}
