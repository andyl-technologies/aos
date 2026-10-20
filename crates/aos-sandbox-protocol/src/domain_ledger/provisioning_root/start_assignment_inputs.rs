//! Frames the accepted Start's read-only current signed-policy input flight.
//!
//! ```text
//! query   = AOSSIQ02 | fixed continuation query fields
//! subject = AOSSIS02 | StartOp | acceptedStartV3 | canonicalRequest |
//!           ReadyB | PrepareRequest | PrepareOutcome | Root6 | currentCAccount
//! reply   = AOSSIR02 | admission144 | signedDeploymentInputs | signedProjectInputs
//! ```
//!
//! The genuine Root reader independently verifies current C, Source and policy
//! custody. These codecs return borrowed DATA only. They issue no resource plan,
//! lease, signature, mutation authority or replacement deadline.

use crate::domain_ledger::create_storage_history::{HistoryErrorV1,
    continuation::framing, outcome::ROOT_CLOSED_RECEIPT_BYTES_V1};
use crate::domain_ledger::{operation::OPERATION_RECORD_V3_BYTES,
    resource_bank::ACCOUNT_HEAD_BYTES_V1};
use aos_sandbox_broker_session_protocol::projection::{
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES};

/// Identifies only the read-only accepted Start policy-input opening.
pub const QUERY_MAGIC_V2: &[u8; 8] = b"AOSSIQ02";
/// Holds the unchanged common fixed query width.
pub const QUERY_BYTES_V2: usize = super::opening::QUERY_BYTES;
/// Holds the exact lease-free original temporal record width.
pub const ADMISSION_BYTES_V2: usize = 144;
/// Holds the common strict three-field reply announcement width.
pub const REPLY_HEADER_BYTES_V2: usize = 20;

const QUERY_DOMAIN_V2: &[u8] = b"aos.sandbox.root.start-assignment-inputs.query.v2\0";
const ADMISSION_MAGIC_V2: &[u8; 8] = b"AOSSIT02";
const SUBJECT_MAGIC_V2: &[u8; 8] = b"AOSSIS02";
const SUBJECT_DOMAIN_V2: &[u8] = b"aos.sandbox.root.start-assignment-inputs.subject.v2\0";
const DEPLOYMENT_MAGIC_V2: &[u8; 8] = b"AOSSDI02";
const PROJECT_MAGIC_V2: &[u8; 8] = b"AOSSPI02";
const REPLY_MAGIC_V2: &[u8; 8] = b"AOSSIR02";
const REPLY_DOMAIN_V2: &[u8] = b"aos.sandbox.root.start-assignment-inputs.reply.v2\0";

/// Carries current-C and original accepted Start comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartAssignmentInputsQueryDataV2 {
    /// The new actual Controller flight's nonce.
    pub controller_nonce: [u8; 16],
    /// The accepted Start first native pair's actual boot identity.
    pub original_boot: [u8; 16],
    /// The accepted Start first native pair's BOOTTIME value.
    pub original_boottime_ns: u64,
    /// The unchanged Start cutoff, already clamped by its original admission.
    pub original_cutoff_ns: u64,
    /// The complete borrowed subject width.
    pub subject_bytes: u64,
    /// The exact purpose-specific subject commitment.
    pub subject_digest: [u8; 32],
    /// The same actual current C journal's NEXT.
    pub controller_next: u64,
    /// The same actual current C journal's durable end.
    pub controller_end: u64,
}

impl StartAssignmentInputsQueryDataV2 {
    /// Decodes exact fixed Start input opening DATA without allocating.
    ///
    /// # Errors
    /// Refuses another purpose, sentinels, invalid times or trailing bytes.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let value = super::opening::QueryFieldsV1::decode(bytes, QUERY_MAGIC_V2)?;
        Ok(Self {
            controller_nonce: value.controller_nonce,
            original_boot: value.original_boot,
            original_boottime_ns: value.original_boottime_ns,
            original_cutoff_ns: value.original_cutoff_ns,
            subject_bytes: value.subject_bytes,
            subject_digest: value.subject_digest,
            controller_next: value.controller_next,
            controller_end: value.controller_end,
        })
    }

    fn fields_v2(self) -> super::opening::QueryFieldsV1 {
        super::opening::QueryFieldsV1 {
            controller_nonce: self.controller_nonce,
            original_boot: self.original_boot,
            original_boottime_ns: self.original_boottime_ns,
            original_cutoff_ns: self.original_cutoff_ns,
            subject_bytes: self.subject_bytes,
            subject_digest: self.subject_digest,
            controller_next: self.controller_next,
            controller_end: self.controller_end,
        }
    }

    /// Encodes the same checked fixed Start input opening DATA.
    ///
    /// # Errors
    /// Refuses invalid original identity, time or extent fields.
    pub fn encode_v2(self) -> Result<[u8; QUERY_BYTES_V2], HistoryErrorV1> {
        self.fields_v2().encode(QUERY_MAGIC_V2)
    }

    /// Commits the whole Start input query, including Start's unchanged horizon.
    ///
    /// # Errors
    /// Refuses invalid fields before hashing.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.fields_v2().digest(QUERY_MAGIC_V2, QUERY_DOMAIN_V2)
    }
}

/// Borrows actual accepted Start and immutable completed Create inputs.
#[derive(Clone, Copy)]
pub struct StartAssignmentInputsSubjectDataV2<'held> {
    /// The actual accepted Start operation key.
    pub start_operation: &'held [u8],
    /// Its exact protected Operation V3 bytes.
    pub accepted_start: &'held [u8],
    /// The same accepted canonical public request.
    pub canonical_request: &'held [u8],
    /// The immutable completed Create Ready B framing.
    pub ready: &'held [u8],
    /// The original authenticated Prepare request.
    pub prepare_request: &'held [u8],
    /// Its committed authenticated Prepare outcome.
    pub prepare_outcome: &'held [u8],
    /// The immutable original Root6 receipt.
    pub root_closed: &'held [u8],
    /// The same current C baseline account head.
    pub controller_account: &'held [u8],
}

impl<'held> StartAssignmentInputsSubjectDataV2<'held> {
    fn fields_v2(self) -> [&'held [u8]; 8] {
        [self.start_operation, self.accepted_start, self.canonical_request, self.ready, self.prepare_request, self.prepare_outcome, self.root_closed, self.controller_account]
    }

    fn maxima_v2() -> [usize; 8] {
        [16, OPERATION_RECORD_V3_BYTES, AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, u32::MAX as usize, AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, ROOT_CLOSED_RECEIPT_BYTES_V1, ACCOUNT_HEAD_BYTES_V1]
    }

    /// Decodes only borrowed canonical framing through the common field codec.
    ///
    /// # Errors
    /// Rejects wrong magic, malformed extents, empty fields or trailing bytes.
    pub fn decode_v2(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
        let [start_operation, accepted_start, canonical_request, ready, prepare_request, prepare_outcome, root_closed, controller_account] = framing::decode_fields(bytes, SUBJECT_MAGIC_V2, Self::maxima_v2())?;
        let value = Self {
            start_operation,
            accepted_start,
            canonical_request,
            ready,
            prepare_request,
            prepare_outcome,
            root_closed,
            controller_account,
        };
        value.encoded_bytes_v2()?;
        Ok(value)
    }

    /// Measures the complete checked framing before any allocation.
    ///
    /// # Errors
    /// Rejects wrong fixed widths, empty fields, exceeded caps or overflow.
    pub fn encoded_bytes_v2(self) -> Result<usize, HistoryErrorV1> {
        if self.start_operation.len() != 16 || self.start_operation == [0; 16]
            || self.accepted_start.len() != OPERATION_RECORD_V3_BYTES
            || self.root_closed.len() != ROOT_CLOSED_RECEIPT_BYTES_V1
            || self.controller_account.len() != ACCOUNT_HEAD_BYTES_V1
        {
            return Err(HistoryErrorV1::Extent);
        }
        for (field, maximum) in self.fields_v2().into_iter().zip(Self::maxima_v2()) {
            if field.is_empty() || field.len() > maximum {
                return Err(HistoryErrorV1::Extent);
            }
        }
        framing::fields_bytes(self.fields_v2())
    }

    /// Copies a checked range from these same borrowed fields.
    ///
    /// # Errors
    /// Rejects invalid framing or a copy outside the complete encoded range.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        framing::encode_fields_range(SUBJECT_MAGIC_V2, self.fields_v2(), offset, output)
    }

    /// Commits every canonical field under this exact read-only purpose.
    ///
    /// # Errors
    /// Rejects invalid framing before hashing.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        super::opening::hash_fields(SUBJECT_DOMAIN_V2, SUBJECT_MAGIC_V2, self.fields_v2())
    }
}

/// Carries Root's actual original Start and current authority temporal DATA.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct StartAssignmentInputsAdmissionDataV2 {
    /// The new actual Root child nonce.
    pub root_nonce: [u8; 16],
    /// The matching actual Controller child nonce.
    pub controller_nonce: [u8; 16],
    /// The exact complete opening query commitment.
    pub query_digest: [u8; 32],
    /// The unchanged first native Start boot identity.
    pub original_boot: [u8; 16],
    /// The unchanged first native Start BOOTTIME coordinate.
    pub original_boottime_ns: u64,
    /// The unchanged absolute Start cutoff.
    pub original_cutoff_ns: u64,
    /// Root's actual independently sampled wall time.
    pub observed_wall_seconds: i64,
    /// Root's actual independently sampled BOOTTIME.
    pub observed_boottime_ns: u64,
    /// The minimum original/accepted/current-policy child cutoff.
    pub cutoff_ns: u64,
    /// The freshly verified signed policy expiry.
    pub policy_expires_seconds: i64,
    /// The immutable accepted Start's absolute wall expiry.
    pub accepted_expires_seconds: i64,
}

impl StartAssignmentInputsAdmissionDataV2 {
    fn validate(self) -> Result<(), HistoryErrorV1> {
        if self.root_nonce == [0; 16]
            || self.controller_nonce == [0; 16]
            || self.query_digest == [0; 32]
            || self.original_boot == [0; 16]
            || self.original_boottime_ns == 0
            || self.original_boottime_ns > self.observed_boottime_ns
            || self.observed_boottime_ns >= self.cutoff_ns
            || self.cutoff_ns > self.original_cutoff_ns
            || self.observed_wall_seconds >= self.policy_expires_seconds
            || self.observed_wall_seconds >= self.accepted_expires_seconds
        {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    /// Decodes fixed lease-free temporal DATA through the bounded reader.
    ///
    /// # Errors
    /// Rejects wrong purpose, invalid original-time relations or trailing bytes.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = aos_sandbox_core::bounded_codec::BoundedReader::new(
            bytes, |_| HistoryErrorV1::Extent,
        );
        if input.array::<8>()? != *ADMISSION_MAGIC_V2 {
            return Err(HistoryErrorV1::Malformed);
        }
        let value = Self {
            root_nonce: input.array()?,
            controller_nonce: input.array()?,
            query_digest: input.array()?,
            original_boot: input.array()?,
            original_boottime_ns: input.u64()?,
            original_cutoff_ns: input.u64()?,
            observed_wall_seconds: input.i64()?,
            observed_boottime_ns: input.u64()?,
            cutoff_ns: input.u64()?,
            policy_expires_seconds: input.i64()?,
            accepted_expires_seconds: input.i64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Encodes the same checked fixed temporal fields as inert DATA.
    ///
    /// # Errors
    /// Rejects invalid identity or original/current policy expiry relations.
    pub fn encode_v2(self) -> Result<[u8; ADMISSION_BYTES_V2], HistoryErrorV1> {
        self.validate()?;
        let mut output = [0; ADMISSION_BYTES_V2];
        output[..8].copy_from_slice(ADMISSION_MAGIC_V2);
        output[8..24].copy_from_slice(&self.root_nonce);
        output[24..40].copy_from_slice(&self.controller_nonce);
        output[40..72].copy_from_slice(&self.query_digest);
        output[72..88].copy_from_slice(&self.original_boot);
        output[88..96].copy_from_slice(&self.original_boottime_ns.to_be_bytes());
        output[96..104].copy_from_slice(&self.original_cutoff_ns.to_be_bytes());
        output[104..112].copy_from_slice(&self.observed_wall_seconds.to_be_bytes());
        output[112..120].copy_from_slice(&self.observed_boottime_ns.to_be_bytes());
        output[120..128].copy_from_slice(&self.cutoff_ns.to_be_bytes());
        output[128..136].copy_from_slice(&self.policy_expires_seconds.to_be_bytes());
        output[136..144].copy_from_slice(&self.accepted_expires_seconds.to_be_bytes());
        Ok(output)
    }
}

/// Borrows a signed deployment packet and its exact existing input envelopes.
#[derive(Clone, Copy)]
pub struct SignedDeploymentInputsDataV2<'held> {
    /// The exact current signed deployment-head packet.
    pub signed_packet: &'held [u8],
    /// The exact canonical node deployment envelope.
    pub node: &'held [u8],
    /// The exact canonical site deployment envelope.
    pub site: &'held [u8],
    /// The exact canonical backend deployment envelope.
    pub backend: &'held [u8],
    /// The exact canonical catalog deployment envelope.
    pub catalogs: &'held [u8],
}

impl<'held> SignedDeploymentInputsDataV2<'held> {
    fn fields_v2(self) -> [&'held [u8]; 5] {
        [self.signed_packet, self.node, self.site, self.backend, self.catalogs]
    }

    fn maxima_v2() -> [usize; 5] {
        [224, 64 * 1024, 64 * 1024, 64 * 1024, 64 * 1024]
    }

    /// Decodes only borrowed canonical framing through the common field codec.
    ///
    /// # Errors
    /// Rejects wrong magic, malformed extents, empty fields or trailing bytes.
    pub fn decode_v2(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
        let [signed_packet, node, site, backend, catalogs] = framing::decode_fields(bytes, DEPLOYMENT_MAGIC_V2, Self::maxima_v2())?;
        let value = Self {
            signed_packet,
            node,
            site,
            backend,
            catalogs,
        };
        value.encoded_bytes_v2()?;
        Ok(value)
    }

    /// Measures the complete checked framing before any allocation.
    ///
    /// # Errors
    /// Rejects wrong fixed widths, empty fields, exceeded caps or overflow.
    pub fn encoded_bytes_v2(self) -> Result<usize, HistoryErrorV1> {
        if self.signed_packet.len() != 224 {
            return Err(HistoryErrorV1::Extent);
        }
        for (field, maximum) in self.fields_v2().into_iter().zip(Self::maxima_v2()) {
            if field.is_empty() || field.len() > maximum {
                return Err(HistoryErrorV1::Extent);
            }
        }
        framing::fields_bytes(self.fields_v2())
    }

    /// Copies a checked range from these same borrowed fields.
    ///
    /// # Errors
    /// Rejects invalid framing or a copy outside the complete encoded range.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        framing::encode_fields_range(DEPLOYMENT_MAGIC_V2, self.fields_v2(), offset, output)
    }
}

/// Borrows a signed project packet and its exact canonical input.
#[derive(Clone, Copy)]
pub struct SignedProjectInputsDataV2<'held> {
    /// The exact current signed project-head packet.
    pub signed_packet: &'held [u8],
    /// The exact canonical signed project input.
    pub input: &'held [u8],
}

impl<'held> SignedProjectInputsDataV2<'held> {
    fn fields_v2(self) -> [&'held [u8]; 2] {
        [self.signed_packet, self.input]
    }

    fn maxima_v2() -> [usize; 2] {
        [328, 3 * 1024]
    }

    /// Decodes only borrowed canonical framing through the common field codec.
    ///
    /// # Errors
    /// Rejects wrong magic, malformed extents, empty fields or trailing bytes.
    pub fn decode_v2(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
        let [signed_packet, input] = framing::decode_fields(bytes, PROJECT_MAGIC_V2, Self::maxima_v2())?;
        let value = Self {
            signed_packet,
            input,
        };
        value.encoded_bytes_v2()?;
        Ok(value)
    }

    /// Measures the complete checked framing before any allocation.
    ///
    /// # Errors
    /// Rejects wrong fixed widths, empty fields, exceeded caps or overflow.
    pub fn encoded_bytes_v2(self) -> Result<usize, HistoryErrorV1> {
        if self.signed_packet.len() != 328 {
            return Err(HistoryErrorV1::Extent);
        }
        for (field, maximum) in self.fields_v2().into_iter().zip(Self::maxima_v2()) {
            if field.is_empty() || field.len() > maximum {
                return Err(HistoryErrorV1::Extent);
            }
        }
        framing::fields_bytes(self.fields_v2())
    }

    /// Copies a checked range from these same borrowed fields.
    ///
    /// # Errors
    /// Rejects invalid framing or a copy outside the complete encoded range.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        framing::encode_fields_range(PROJECT_MAGIC_V2, self.fields_v2(), offset, output)
    }
}

/// Borrows only current signed input DATA from the actual Root read flight.
#[derive(Clone, Copy)]
pub struct StartAssignmentInputsReplyDataV2<'held> {
    /// The exact lease-free temporal comparison record.
    pub admission: &'held [u8],
    /// The complete canonical signed deployment-input envelope.
    pub deployment: &'held [u8],
    /// The complete canonical signed project-input envelope.
    pub project: &'held [u8],
}

impl<'held> StartAssignmentInputsReplyDataV2<'held> {
    fn fields_v2(self) -> [&'held [u8]; 3] {
        [self.admission, self.deployment, self.project]
    }

    fn maxima_v2() -> [usize; 3] {
        [ADMISSION_BYTES_V2, 8 + 5 * 4 + 224 + 4 * 64 * 1024, 8 + 2 * 4 + 328 + 3 * 1024]
    }

    /// Decodes only borrowed canonical framing through the common field codec.
    ///
    /// # Errors
    /// Rejects wrong magic, malformed extents, empty fields or trailing bytes.
    pub fn decode_v2(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
        let [admission, deployment, project] = framing::decode_fields(bytes, REPLY_MAGIC_V2, Self::maxima_v2())?;
        let value = Self {
            admission,
            deployment,
            project,
        };
        value.encoded_bytes_v2()?;
        Ok(value)
    }

    /// Measures the complete checked framing before any allocation.
    ///
    /// # Errors
    /// Rejects wrong fixed widths, empty fields, exceeded caps or overflow.
    pub fn encoded_bytes_v2(self) -> Result<usize, HistoryErrorV1> {
        StartAssignmentInputsAdmissionDataV2::decode_v2(self.admission)?;
        SignedDeploymentInputsDataV2::decode_v2(self.deployment)?;
        SignedProjectInputsDataV2::decode_v2(self.project)?;
        for (field, maximum) in self.fields_v2().into_iter().zip(Self::maxima_v2()) {
            if field.is_empty() || field.len() > maximum {
                return Err(HistoryErrorV1::Extent);
            }
        }
        framing::fields_bytes(self.fields_v2())
    }

    /// Copies a checked range from these same borrowed fields.
    ///
    /// # Errors
    /// Rejects invalid framing or a copy outside the complete encoded range.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        framing::encode_fields_range(REPLY_MAGIC_V2, self.fields_v2(), offset, output)
    }

    /// Commits every canonical field under this exact read-only purpose.
    ///
    /// # Errors
    /// Rejects invalid framing before hashing.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        super::opening::hash_fields(REPLY_DOMAIN_V2, REPLY_MAGIC_V2, self.fields_v2())
    }
}

impl StartAssignmentInputsReplyDataV2<'_> {
    /// Measures the announced complete reply before growing its receive owner.
    ///
    /// # Errors
    /// Rejects another purpose, wrong fixed temporal width or exceeded field caps.
    pub fn declared_bytes_v2(header: &[u8]) -> Result<usize, HistoryErrorV1> {
        let bytes = framing::declared_fields_bytes(header, REPLY_MAGIC_V2, Self::maxima_v2())?;
        if header.get(8..12) != Some((ADMISSION_BYTES_V2 as u32).to_be_bytes().as_slice()) {
            return Err(HistoryErrorV1::Extent);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_query_has_its_own_purpose_and_never_moves_the_original_cutoff() {
        let query = StartAssignmentInputsQueryDataV2 {
            controller_nonce: [1; 16], original_boot: [2; 16],
            original_boottime_ns: 10, original_cutoff_ns: 20,
            subject_bytes: 1, subject_digest: [3; 32], controller_next: 1, controller_end: 1,
        };
        let encoded = query.encode_v2().unwrap();

        assert_eq!(StartAssignmentInputsQueryDataV2::decode_v2(&encoded).unwrap(), query);
        assert!(super::super::host_launch::HostLaunchQueryDataV1::decode_v1(&encoded).is_err());
        assert!(StartAssignmentInputsQueryDataV2 { original_cutoff_ns: 10, ..query }
            .encode_v2().is_err());
    }

    #[test]
    fn input_admission_has_no_lease_or_resource_admission_encoding() {
        let admission = StartAssignmentInputsAdmissionDataV2 {
            root_nonce: [1; 16], controller_nonce: [2; 16], query_digest: [3; 32],
            original_boot: [4; 16], original_boottime_ns: 10, original_cutoff_ns: 30,
            observed_wall_seconds: 100, observed_boottime_ns: 20, cutoff_ns: 25,
            policy_expires_seconds: 110, accepted_expires_seconds: 105,
        };
        let encoded = admission.encode_v2().unwrap();

        assert_eq!(encoded.len(), 144);
        assert_eq!(StartAssignmentInputsAdmissionDataV2::decode_v2(&encoded).unwrap(), admission);
        assert!(super::super::host_launch::HostResourceAdmissionDataV1::decode_v1(&encoded).is_err());
        assert!(StartAssignmentInputsAdmissionDataV2 { observed_wall_seconds: 105, ..admission }
            .encode_v2().is_err());
    }
}
