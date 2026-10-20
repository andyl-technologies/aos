//! Frames the current Maintenance interval's distinct Storage31 Root purpose.
//!
//! ```text
//! query   = AOSMSQ02 | common fixed Root opening fields
//! subject = AOSMSS02 | reservation320 | deadlineFree31 | signed18Request |
//!           signed18Outcome | currentCAccount | actualSourceNative64 |
//!           actualStorageSessionNative64
//! ```
//!
//! The unchanged mechanical horizon belongs to the actual held Maintenance F.
//! Root independently verifies its current native C/Source/Storage cuts and
//! live assignment/lease. The reservation fixes inert effect identity; neither
//! its bytes nor these framing values establish an accepted Start or a grant.

use crate::domain_ledger::create_storage_history::{HistoryErrorV1, continuation::framing};
use crate::domain_ledger::resource_bank::ACCOUNT_HEAD_BYTES_V1;
use aos_sandbox_broker_session_protocol::projection::{
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES as REQUEST_MAXIMUM,
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as RESPONSE_MAXIMUM,
};

/// Identifies the distinct current Maintenance Storage opening.
pub const QUERY_MAGIC_V2: &[u8; 8] = b"AOSMSQ02";

/// Holds the common exact fixed query width.
pub const QUERY_BYTES_V2: usize = super::opening::QUERY_BYTES;

/// Bounds one Maintenance F by its original mechanical transport ceiling.
pub const TRANSPORT_CEILING_NANOSECONDS_V2: u64 = 10_000_000_000;

const QUERY_DOMAIN_V2: &[u8] = b"aos.sandbox.root.maintenance-storage.query.v2\0";
const SUBJECT_MAGIC_V2: &[u8; 8] = b"AOSMSS02";
const SUBJECT_DOMAIN_V2: &[u8] = b"aos.sandbox.root.maintenance-storage.subject.v2\0";

/// Holds the fixed width of Root's temporal comparison DATA.
pub const ADMISSION_BYTES_V2: usize = 144;

/// Holds the three-field reply's fixed framing prefix.
pub const REPLY_HEADER_BYTES_V2: usize = 20;

const ADMISSION_MAGIC_V2: &[u8; 8] = b"AOSMSA02";
const REPLY_MAGIC_V2: &[u8; 8] = b"AOSMSR02";
const REPLY_DOMAIN_V2: &[u8] = b"aos.sandbox.root.maintenance-storage.reply.v2\0";

/// Carries the current C cut and continuously held Maintenance horizon as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceStorageQueryDataV2 {
    /// The new actual Controller Root child's nonce.
    pub controller_nonce: [u8; 16],
    /// The actual Maintenance first paired clock's boot identity.
    pub original_boot: [u8; 16],
    /// That same first paired clock's BOOTTIME coordinate.
    pub original_boottime_ns: u64,
    /// The unchanged absolute cutoff of this same held F.
    pub original_cutoff_ns: u64,
    /// The complete finite subject extent.
    pub subject_bytes: u64,
    /// The exact purpose-specific subject commitment.
    pub subject_digest: [u8; 32],
    /// The actual current C journal's NEXT.
    pub controller_next: u64,
    /// The actual current C journal's durable end.
    pub controller_end: u64,
}

impl MaintenanceStorageQueryDataV2 {
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

    fn require_ceiling_v2(self) -> Result<(), HistoryErrorV1> {
        if self.original_cutoff_ns.checked_sub(self.original_boottime_ns)
            .is_none_or(|width| width == 0 || width > TRANSPORT_CEILING_NANOSECONDS_V2)
        {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    /// Decodes only the exact Maintenance purpose through the common codec.
    ///
    /// # Errors
    /// Refuses another purpose, invalid fixed fields, an enlarged original
    /// ceiling, or trailing bytes.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let fields = super::opening::QueryFieldsV1::decode(bytes, QUERY_MAGIC_V2)?;
        let value = Self {
            controller_nonce: fields.controller_nonce,
            original_boot: fields.original_boot,
            original_boottime_ns: fields.original_boottime_ns,
            original_cutoff_ns: fields.original_cutoff_ns,
            subject_bytes: fields.subject_bytes,
            subject_digest: fields.subject_digest,
            controller_next: fields.controller_next,
            controller_end: fields.controller_end,
        };
        value.require_ceiling_v2()?;
        Ok(value)
    }

    /// Encodes the same current-F comparison fields without creating authority.
    ///
    /// # Errors
    /// Refuses invalid fixed fields or an enlarged original transport ceiling.
    pub fn encode_v2(self) -> Result<[u8; QUERY_BYTES_V2], HistoryErrorV1> {
        self.require_ceiling_v2()?;
        self.fields_v2().encode(QUERY_MAGIC_V2)
    }

    /// Commits the exact Maintenance query under its own domain.
    ///
    /// # Errors
    /// Refuses invalid fixed fields or an enlarged original transport ceiling.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.require_ceiling_v2()?;
        self.fields_v2().digest(QUERY_MAGIC_V2, QUERY_DOMAIN_V2)
    }
}

/// Borrows the actual reservation, signed snapshot and current native cuts.
#[derive(Clone, Copy)]
pub struct MaintenanceStorageSubjectDataV2<'held> {
    /// The exact protected AOSGRR01 record selected from current C.
    pub reservation: &'held [u8],
    /// The exact deadline-free method31 request for that reserved identity.
    pub request_body: &'held [u8],
    /// The actual freshly authenticated Storage18 request on the held Session.
    pub inventory_request: &'held [u8],
    /// Its actual committed signed terminal outcome.
    pub inventory_outcome: &'held [u8],
    /// The actual current C baseline account head.
    pub controller_account: &'held [u8],
    /// The actual held current Source names, NEXT and durable boundary.
    pub source_native: &'held [u8],
    /// The same actual completed Storage Session's names, NEXT and boundary.
    pub session_native: &'held [u8],
}

impl<'held> MaintenanceStorageSubjectDataV2<'held> {
    fn fields_v2(self) -> [&'held [u8]; 7] {
        [self.reservation, self.request_body, self.inventory_request,
            self.inventory_outcome, self.controller_account,
            self.source_native, self.session_native]
    }

    fn maxima_v2() -> [usize; 7] {
        [320, REQUEST_MAXIMUM, REQUEST_MAXIMUM, RESPONSE_MAXIMUM,
            ACCOUNT_HEAD_BYTES_V1, 64, 64]
    }

    /// Decodes borrowed fields through the sole finite framing engine.
    ///
    /// # Errors
    /// Refuses another purpose, invalid widths, empty fields, exceeded caps,
    /// or trailing bytes. Native and canonical record verification remain owed.
    pub fn decode_v2(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
        let [reservation, request_body, inventory_request, inventory_outcome,
            controller_account, source_native, session_native] = framing::decode_fields(
                bytes, SUBJECT_MAGIC_V2, Self::maxima_v2())?;
        let value = Self { reservation, request_body, inventory_request,
            inventory_outcome, controller_account, source_native, session_native };
        value.encoded_bytes_v2()?;
        Ok(value)
    }

    /// Measures the complete framing before any aggregate allocation.
    ///
    /// # Errors
    /// Refuses invalid fixed widths, empty fields, exceeded caps or overflow.
    pub fn encoded_bytes_v2(self) -> Result<usize, HistoryErrorV1> {
        if self.reservation.len() != 320
            || self.controller_account.len() != ACCOUNT_HEAD_BYTES_V1
            || self.source_native.len() != 64
            || self.session_native.len() != 64
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

    /// Copies a checked range from the same exact borrowed originals.
    ///
    /// # Errors
    /// Refuses invalid framing or a range outside the complete encoding.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        framing::encode_fields_range(SUBJECT_MAGIC_V2, self.fields_v2(), offset, output)
    }

    /// Commits all fields under the distinct Maintenance subject domain.
    ///
    /// # Errors
    /// Refuses invalid framing or overflow before hashing.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        super::opening::hash_fields(SUBJECT_DOMAIN_V2, SUBJECT_MAGIC_V2, self.fields_v2())
    }
}

/// Carries Root's actual original Maintenance and current authority temporal DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceStorageAdmissionDataV2 {
    /// The new actual Root child's nonce.
    pub root_nonce: [u8; 16],
    /// The matching actual Controller child's nonce.
    pub controller_nonce: [u8; 16],
    /// The complete purpose-specific opening commitment.
    pub query_digest: [u8; 32],
    /// The unchanged Maintenance first native boot identity.
    pub original_boot: [u8; 16],
    /// The unchanged Maintenance first native BOOTTIME coordinate.
    pub original_boottime_ns: u64,
    /// The unchanged absolute Maintenance mechanical cutoff.
    pub original_cutoff_ns: u64,
    /// Root's independently sampled wall coordinate.
    pub observed_wall_seconds: i64,
    /// Root's independently sampled BOOTTIME coordinate.
    pub observed_boottime_ns: u64,
    /// The minimum original, fresh policy, and fresh lease cutoff.
    pub cutoff_ns: u64,
    /// The freshly verified signed policy expiry.
    pub policy_expires_seconds: i64,
    /// The freshly verified live lease expiry.
    pub lease_expires_seconds: i64,
}

impl MaintenanceStorageAdmissionDataV2 {
    fn fields_v2(self) -> super::opening::TemporalAdmissionFieldsV2<2> {
        super::opening::TemporalAdmissionFieldsV2 {
            root_nonce: self.root_nonce, controller_nonce: self.controller_nonce,
            query_digest: self.query_digest, original_boot: self.original_boot,
            original_boottime_ns: self.original_boottime_ns,
            original_cutoff_ns: self.original_cutoff_ns,
            observed_wall_seconds: self.observed_wall_seconds,
            observed_boottime_ns: self.observed_boottime_ns, cutoff_ns: self.cutoff_ns,
            authority_expiries: [self.policy_expires_seconds, self.lease_expires_seconds],
        }
    }

    fn require_ceiling_v2(self) -> Result<(), HistoryErrorV1> {
        if self.original_cutoff_ns.checked_sub(self.original_boottime_ns)
            .is_none_or(|width| width == 0 || width > TRANSPORT_CEILING_NANOSECONDS_V2) {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    /// Decodes the exact closed temporal record without adopting its authority.
    ///
    /// # Errors
    /// Refuses another purpose, extended original horizon, invalid temporal
    /// relation, expired policy or lease, or trailing bytes.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let value = super::opening::TemporalAdmissionFieldsV2::<2>::decode(bytes, ADMISSION_MAGIC_V2)?;
        let admission = Self {
            root_nonce: value.root_nonce, controller_nonce: value.controller_nonce,
            query_digest: value.query_digest, original_boot: value.original_boot,
            original_boottime_ns: value.original_boottime_ns,
            original_cutoff_ns: value.original_cutoff_ns,
            observed_wall_seconds: value.observed_wall_seconds,
            observed_boottime_ns: value.observed_boottime_ns, cutoff_ns: value.cutoff_ns,
            policy_expires_seconds: value.authority_expiries[0],
            lease_expires_seconds: value.authority_expiries[1],
        };
        admission.require_ceiling_v2()?;
        Ok(admission)
    }

    /// Encodes the same original and fresh Root observations as passive DATA.
    ///
    /// # Errors
    /// Refuses an extended original horizon or invalid authority/time relation.
    pub fn encode_v2(self) -> Result<[u8; ADMISSION_BYTES_V2], HistoryErrorV1> {
        self.require_ceiling_v2()?;
        self.fields_v2().encode(ADMISSION_MAGIC_V2)
    }
}

/// Borrows the exact unsigned Maintenance plan and public signing statement.
#[derive(Clone, Copy)]
pub struct MaintenanceStorageReplyDataV2<'held> {
    /// The fixed original/fresh temporal comparison DATA.
    pub admission: &'held [u8],
    /// The exact independently normalized unsigned plan.
    pub canonical_plan: &'held [u8],
    /// The exact corresponding canonical public signing statement.
    pub canonical_statement: &'held [u8],
}

impl<'held> MaintenanceStorageReplyDataV2<'held> {
    fn fields_v2(self) -> [&'held [u8]; 3] {
        [self.admission, self.canonical_plan, self.canonical_statement]
    }

    fn maxima_v2() -> [usize; 3] {
        [ADMISSION_BYTES_V2, u32::MAX as usize, u32::MAX as usize]
    }

    /// Measures the announced reply before receiving any aggregate allocation.
    ///
    /// # Errors
    /// Refuses wrong purpose, fixed width, empty fields, or an exceeded cap.
    pub fn declared_bytes_v2(header: &[u8]) -> Result<usize, HistoryErrorV1> {
        let width = framing::declared_fields_bytes(header, REPLY_MAGIC_V2, Self::maxima_v2())?;
        if header.get(8..12) != Some((ADMISSION_BYTES_V2 as u32).to_be_bytes().as_slice()) {
            return Err(HistoryErrorV1::Extent);
        }
        Ok(width)
    }

    /// Decodes exact borrowed reply framing without creating a permission.
    ///
    /// # Errors
    /// Refuses another purpose, invalid nested temporal record or trailing bytes.
    pub fn decode_v2(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
        let [admission, canonical_plan, canonical_statement] = framing::decode_fields(
            bytes, REPLY_MAGIC_V2, Self::maxima_v2())?;
        let reply = Self { admission, canonical_plan, canonical_statement };
        reply.encoded_bytes_v2()?;
        Ok(reply)
    }

    /// Measures checked reply DATA without allocation or authority.
    ///
    /// # Errors
    /// Refuses invalid fixed temporal DATA or nested field bounds.
    pub fn encoded_bytes_v2(self) -> Result<usize, HistoryErrorV1> {
        MaintenanceStorageAdmissionDataV2::decode_v2(self.admission)?;
        for (field, maximum) in self.fields_v2().into_iter().zip(Self::maxima_v2()) {
            if field.is_empty() || field.len() > maximum { return Err(HistoryErrorV1::Extent); }
        }
        framing::fields_bytes(self.fields_v2())
    }

    /// Copies one checked range from the same exact reply originals.
    ///
    /// # Errors
    /// Refuses invalid framing or a range outside the complete encoding.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        framing::encode_fields_range(REPLY_MAGIC_V2, self.fields_v2(), offset, output)
    }

    /// Commits exact reply framing under the closed Maintenance domain.
    ///
    /// # Errors
    /// Refuses invalid nested temporal DATA, field bounds or overflow.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        super::opening::hash_fields(REPLY_DOMAIN_V2, REPLY_MAGIC_V2, self.fields_v2())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> MaintenanceStorageQueryDataV2 {
        MaintenanceStorageQueryDataV2 {
            controller_nonce: [1; 16], original_boot: [2; 16],
            original_boottime_ns: 1_000_000_000,
            original_cutoff_ns: 11_000_000_000,
            subject_bytes: 64, subject_digest: [3; 32],
            controller_next: 1, controller_end: 1,
        }
    }

    #[test]
    fn maintenance_query_refuses_start_purpose_and_extended_original_horizon() {
        let original = query();
        let encoded = original.encode_v2().unwrap();
        assert_eq!(MaintenanceStorageQueryDataV2::decode_v2(&encoded).unwrap(), original);

        let mut start = encoded;
        start[..8].copy_from_slice(super::super::host_launch::QUERY_MAGIC_V1);
        assert!(MaintenanceStorageQueryDataV2::decode_v2(&start).is_err());

        let extended = MaintenanceStorageQueryDataV2 {
            original_cutoff_ns: original.original_cutoff_ns + 1,
            ..original
        };
        assert!(extended.encode_v2().is_err());
        let mut untrusted = encoded;
        untrusted[48..56].copy_from_slice(&extended.original_cutoff_ns.to_be_bytes());
        assert!(MaintenanceStorageQueryDataV2::decode_v2(&untrusted).is_err());
    }

    #[test]
    fn maintenance_temporal_data_requires_original_cutoff_and_both_current_authorities() {
        let admission = MaintenanceStorageAdmissionDataV2 {
            root_nonce: [1; 16], controller_nonce: [2; 16], query_digest: [3; 32],
            original_boot: [4; 16], original_boottime_ns: 1_000_000_000,
            original_cutoff_ns: 11_000_000_000, observed_wall_seconds: 100,
            observed_boottime_ns: 2_000_000_000, cutoff_ns: 9_000_000_000,
            policy_expires_seconds: 110, lease_expires_seconds: 120,
        };
        let encoded = admission.encode_v2().unwrap();
        assert_eq!(MaintenanceStorageAdmissionDataV2::decode_v2(&encoded).unwrap(), admission);

        for changed in [
            MaintenanceStorageAdmissionDataV2 { policy_expires_seconds: 100, ..admission },
            MaintenanceStorageAdmissionDataV2 { lease_expires_seconds: 100, ..admission },
            MaintenanceStorageAdmissionDataV2 { cutoff_ns: 11_000_000_001, ..admission },
        ] {
            assert!(changed.encode_v2().is_err());
        }
        let mut start = encoded;
        start[..8].copy_from_slice(b"AOSHLT01");
        assert!(MaintenanceStorageAdmissionDataV2::decode_v2(&start).is_err());
    }
}
