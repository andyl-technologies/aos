//! Frames the undeployed fixed-purpose Root Storage Apply continuation.
//!
//! ```text
//! query = AOSAPQ01 | ControllerNonce16 | originalBoot16 | originalMono8 |
//!         originalCutoff8 | subjectLength8 | subjectDigest32 | Cnext8 | Cend8
//! subject = AOSAPS01 | five:u32be lengths | ReadyB | PrepareRequest |
//!           PrepareOutcome | Root6Receipt | actualControllerAccountHead
//! reply = AOSAPR01 | three:u32be lengths | temporalData152 | plan | statement
//! ```
//!
//! Request/response ceilings are their existing nested protocol limits; Ready
//! preserves its complete u32 nested framing without a new aggregate cap. All
//! announced extents need actual purpose-specific payment before allocation.
//! This grammar never adopts a signed plan, remints the old Root8 grant or
//! turns account/receipt/clock DATA into an original or currentness proof.

use aos_sandbox_core::bounded_codec::BoundedReader;
use aos_sandbox_broker_session_protocol::projection::{
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
};
use sha2::{Digest as _, Sha256};

use crate::domain_ledger::create_storage_history::{HistoryErrorV1,
    continuation::framing,
    outcome::ROOT_CLOSED_RECEIPT_BYTES_V1};
use crate::domain_ledger::resource_bank::ACCOUNT_HEAD_BYTES_V1;

/// Identifies only the separately funded Root Storage Apply opening.
pub const QUERY_MAGIC_V1: &[u8; 8] = b"AOSAPQ01";
/// Holds the complete fixed query width.
pub const QUERY_BYTES_V1: usize = 112;
/// Holds the exact reply's original temporal comparison DATA width.
pub const ADMISSION_DATA_BYTES_V1: usize = 152;
const SUBJECT_MAGIC: &[u8; 8] = b"AOSAPS01";
const REPLY_MAGIC: &[u8; 8] = b"AOSAPR01";
const ADMISSION_MAGIC: &[u8; 8] = b"AOSAPA01";
const SUBJECT_DOMAIN: &[u8] = b"aos.sandbox.root.storage-apply.subject.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.sandbox.root.storage-apply.reply.v1\0";
const FINAL_DOMAIN: &[u8] = b"aos.sandbox.root.storage-apply.final.v1\0";
const QUERY_DOMAIN: &[u8] = b"aos.sandbox.root.storage-apply.query.v1\0";

/// Reports malformed or substituted Apply exchange DATA.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum ApplyRootDataErrorV1 {
    /// The closed metadata-finality stream adapter refused its fixed DATA.
    #[error(transparent)]
    Finality(#[from] super::finality_recover::FinalityRecoverDataErrorV1),
    /// The fixed purpose, identity or immutable temporal relation differs.
    #[error("Root Storage Apply data is malformed")]
    Malformed,
    /// A nested or aggregate wire extent is invalid.
    #[error("Root Storage Apply extent is invalid")]
    Extent,
    /// The existing finite borrowed-field engine refused its framing.
    #[error(transparent)]
    Fields(#[from] HistoryErrorV1),
}

type Result<T> = std::result::Result<T, ApplyRootDataErrorV1>;

/// Carries nonauthorizing opening and actual current-C comparison fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StorageApplyQueryDataV1 {
    /// The genuine new Controller flight's nonce.
    pub controller_nonce: [u8; 16],
    /// The original Create paired sample's boot identity.
    pub original_boot: [u8; 16],
    /// The original Create paired sample's BOOTTIME value.
    pub original_boottime_ns: u64,
    /// The unchanged original accepted Create cutoff.
    pub original_cutoff_ns: u64,
    /// The complete exact borrowed subject width.
    pub subject_bytes: u64,
    /// The purpose-specific commitment to that complete subject.
    pub subject_digest: [u8; 32],
    /// The actual same Controller journal's current NEXT.
    pub controller_next: u64,
    /// The actual same Controller journal's current durable end.
    pub controller_end: u64,
}

impl StorageApplyQueryDataV1 {
    /// Decodes one exact Apply opening through the common fixed DATA codec.
    ///
    /// # Errors
    /// Rejects wrong purpose, sentinel identities, invalid times or trailing bytes.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self> {
        let value = super::opening::QueryFieldsV1::decode(bytes, QUERY_MAGIC_V1)
            .map_err(query_error)?;
        Ok(Self { controller_nonce: value.controller_nonce, original_boot: value.original_boot, original_boottime_ns: value.original_boottime_ns, original_cutoff_ns: value.original_cutoff_ns, subject_bytes: value.subject_bytes, subject_digest: value.subject_digest, controller_next: value.controller_next, controller_end: value.controller_end })
    }

    fn fields_v1(self) -> super::opening::QueryFieldsV1 {
        let Self { controller_nonce, original_boot, original_boottime_ns, original_cutoff_ns, subject_bytes, subject_digest, controller_next, controller_end } = self;
        super::opening::QueryFieldsV1 { controller_nonce, original_boot, original_boottime_ns, original_cutoff_ns, subject_bytes, subject_digest, controller_next, controller_end }
    }

    /// Encodes the same exact fixed Apply opening fields.
    ///
    /// # Errors
    /// Rejects the same invalid fields as decoding.
    pub fn encode_v1(self) -> Result<[u8; QUERY_BYTES_V1]> {
        self.fields_v1().encode(QUERY_MAGIC_V1).map_err(query_error)
    }

    /// Commits the complete original Apply query and unchanged cutoff.
    ///
    /// # Errors
    /// Rejects malformed fields before hashing.
    pub fn digest_v1(self) -> Result<[u8; 32]> {
        self.fields_v1().digest(QUERY_MAGIC_V1, QUERY_DOMAIN).map_err(query_error)
    }
}

fn query_error(cause: HistoryErrorV1) -> ApplyRootDataErrorV1 {
    match cause {
        HistoryErrorV1::Malformed => ApplyRootDataErrorV1::Malformed,
        HistoryErrorV1::Extent => ApplyRootDataErrorV1::Extent,
        cause => ApplyRootDataErrorV1::Fields(cause),
    }
}

/// Borrows only actual original Storage completion and Controller inputs.
#[derive(Clone, Copy)]
pub struct StorageApplySubjectDataV1<'a> {
    /// The complete original Ready B frame, including its original lease.
    pub ready: &'a [u8],
    /// The exact authenticated Prepare request packet.
    pub prepare_request: &'a [u8],
    /// Its exact committed authenticated Prepare outcome packet.
    pub prepare_outcome: &'a [u8],
    /// The actual completed Root6 native receipt.
    pub root_closed: &'a [u8],
    /// The actual current Controller baseline AccountHead, not a new C23 claim.
    pub controller_account: &'a [u8],
}

impl<'a> StorageApplySubjectDataV1<'a> {
    fn fields_v1(self) -> [&'a [u8]; 5] {
        [self.ready, self.prepare_request, self.prepare_outcome, self.root_closed, self.controller_account]
    }

    /// Borrows exact original fields through the existing shared framing engine.
    ///
    /// # Errors
    /// Refuses malformed framing, empty fields or an existing nested cap violation.
    pub fn decode_v1(bytes: &'a [u8]) -> Result<Self> {
        let [ready, prepare_request, prepare_outcome, root_closed, controller_account] =
            framing::decode_fields(bytes, SUBJECT_MAGIC, [u32::MAX as usize,
                AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
                ROOT_CLOSED_RECEIPT_BYTES_V1, ACCOUNT_HEAD_BYTES_V1])?;
        let value = Self { ready, prepare_request, prepare_outcome, root_closed, controller_account };
        value.encoded_bytes_v1()?;
        Ok(value)
    }

    /// Measures complete framing before any producer allocation.
    ///
    /// # Errors
    /// Refuses empty/oversized fields, nonexact fixed receipts or overflow.
    pub fn encoded_bytes_v1(self) -> Result<usize> {
        if self.prepare_request.len() > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES
            || self.prepare_outcome.len() > AUTHENTICATED_RESPONSE_MAXIMUM_BYTES
            || self.root_closed.len() != ROOT_CLOSED_RECEIPT_BYTES_V1
            || self.controller_account.len() != ACCOUNT_HEAD_BYTES_V1
        { return Err(ApplyRootDataErrorV1::Extent); }
        Ok(framing::fields_bytes(self.fields_v1())?)
    }

    /// Copies only the requested bounded range from the same borrowed originals.
    ///
    /// # Errors
    /// Rejects invalid framing or a range outside the exact complete encoding.
    pub fn encode_range_v1(self, offset: usize, output: &mut [u8]) -> Result<()> {
        self.encoded_bytes_v1()?;
        Ok(framing::encode_fields_range(SUBJECT_MAGIC, self.fields_v1(), offset, output)?)
    }

    /// Hashes complete canonical framing without aggregating large packets.
    ///
    /// # Errors
    /// Rejects malformed fields or arithmetic overflow before hashing.
    pub fn digest_v1(self) -> Result<[u8; 32]> {
        self.encoded_bytes_v1()?;
        hash_fields_v1(SUBJECT_DOMAIN, SUBJECT_MAGIC, self.fields_v1())
    }
}

/// Carries actual Root's original temporal comparison inputs, never a grant.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StorageApplyAdmissionDataV1 {
    /// The new genuine Root purpose's nonce.
    pub root_nonce: [u8; 16],
    /// The original Controller nonce from this query.
    pub controller_nonce: [u8; 16],
    /// The exact whole query commitment.
    pub query_digest: [u8; 32],
    /// The shared original paired boot identity.
    pub original_boot: [u8; 16],
    /// The original Create paired BOOTTIME value.
    pub original_boottime_ns: u64,
    /// The unchanged original Create cutoff.
    pub original_cutoff_ns: u64,
    /// The actual fresh Root sample's wall seconds.
    pub observed_wall_seconds: i64,
    /// The actual fresh Root sample's BOOTTIME value.
    pub observed_boottime_ns: u64,
    /// The minimum original, Prepare, Root-flight and verified authority cutoff.
    pub cutoff_ns: u64,
    /// The actual independently compiled policy's minimum signed-source expiry.
    pub policy_expires_seconds: i64,
    /// The actual independently verified lease's expiry.
    pub lease_expires_seconds: i64,
    /// The actual stored Prepare response's original expiry.
    pub preparation_expires_boottime_ns: u64,
}

impl StorageApplyAdmissionDataV1 {
    fn validate_v1(self) -> Result<()> {
        if self.root_nonce == [0; 16] || self.controller_nonce == [0; 16]
            || self.query_digest == [0; 32] || self.original_boot == [0; 16]
            || self.original_boottime_ns == 0
            || self.observed_boottime_ns < self.original_boottime_ns
            || self.cutoff_ns <= self.observed_boottime_ns
            || self.cutoff_ns > self.original_cutoff_ns
            || self.cutoff_ns > self.preparation_expires_boottime_ns
            || self.observed_wall_seconds <= 0
            || self.policy_expires_seconds <= self.observed_wall_seconds
            || self.lease_expires_seconds <= self.observed_wall_seconds
        { return Err(ApplyRootDataErrorV1::Malformed); }
        Ok(())
    }

    /// Decodes exact immutable temporal DATA without reconstructing a clock owner.
    ///
    /// # Errors
    /// Rejects wrong purpose, invalid original horizon or nonexact framing.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *ADMISSION_MAGIC { return Err(ApplyRootDataErrorV1::Malformed); }
        let value = Self { root_nonce: input.array()?, controller_nonce: input.array()?, query_digest: input.array()?,
            original_boot: input.array()?, original_boottime_ns: input.u64()?, original_cutoff_ns: input.u64()?,
            observed_wall_seconds: input.i64()?, observed_boottime_ns: input.u64()?, cutoff_ns: input.u64()?,
            policy_expires_seconds: input.i64()?, lease_expires_seconds: input.i64()?,
            preparation_expires_boottime_ns: input.u64()? };
        input.finish()?;
        value.validate_v1()?;
        Ok(value)
    }

    /// Encodes exact original temporal fields; this creates no admission owner.
    ///
    /// # Errors
    /// Rejects malformed original horizons and expiry relations.
    pub fn encode_v1(self) -> Result<[u8; ADMISSION_DATA_BYTES_V1]> {
        self.validate_v1()?;
        let mut output = [0; ADMISSION_DATA_BYTES_V1];
        output[..8].copy_from_slice(ADMISSION_MAGIC);
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
        output[136..144].copy_from_slice(&self.lease_expires_seconds.to_be_bytes());
        output[144..152].copy_from_slice(&self.preparation_expires_boottime_ns.to_be_bytes());
        Ok(output)
    }
}

/// Borrows Root's exact independently normalized unsigned output.
#[derive(Clone, Copy)]
pub struct StorageApplyReplyDataV1<'a> {
    /// The exact encoded immutable temporal DATA from the same Root owner.
    pub admission: &'a [u8],
    /// The independently normalized canonical unsigned plan.
    pub canonical_plan: &'a [u8],
    /// The exact signing statement derived from that plan and Root-held public trust.
    pub canonical_statement: &'a [u8],
}

impl<'a> StorageApplyReplyDataV1<'a> {
    fn fields_v1(self) -> [&'a [u8]; 3] { [self.admission, self.canonical_plan, self.canonical_statement] }

    /// Measures an exact 20-byte header before any receiving-buffer growth.
    ///
    /// # Errors
    /// Rejects another purpose, a temporal width other than 152, empty fields,
    /// nonexact header framing or an aggregate width overflow.
    pub fn declared_encoded_bytes_v1(header: &[u8]) -> Result<usize> {
        let total = framing::declared_fields_bytes(header, REPLY_MAGIC,
            [ADMISSION_DATA_BYTES_V1, u32::MAX as usize, u32::MAX as usize])?;
        if header.get(8..12) != Some((ADMISSION_DATA_BYTES_V1 as u32).to_be_bytes().as_slice()) {
            return Err(ApplyRootDataErrorV1::Extent);
        }
        Ok(total)
    }

    /// Borrows the exact three-field output using the existing shared engine.
    ///
    /// # Errors
    /// Rejects malformed framing, fixed temporal width or invalid horizons.
    pub fn decode_v1(bytes: &'a [u8]) -> Result<Self> {
        let [admission, canonical_plan, canonical_statement] = framing::decode_fields(
            bytes, REPLY_MAGIC, [ADMISSION_DATA_BYTES_V1, u32::MAX as usize, u32::MAX as usize])?;
        StorageApplyAdmissionDataV1::decode_v1(admission)?;
        Ok(Self { admission, canonical_plan, canonical_statement })
    }

    /// Measures the complete exact output before receiver growth.
    ///
    /// # Errors
    /// Refuses malformed temporal DATA, empty fields or width overflow.
    pub fn encoded_bytes_v1(self) -> Result<usize> {
        StorageApplyAdmissionDataV1::decode_v1(self.admission)?;
        Ok(framing::fields_bytes(self.fields_v1())?)
    }

    /// Copies only a paid bounded output range, without cloning its plan.
    ///
    /// # Errors
    /// Refuses invalid framing or a range outside the exact complete output.
    pub fn encode_range_v1(self, offset: usize, output: &mut [u8]) -> Result<()> {
        self.encoded_bytes_v1()?;
        Ok(framing::encode_fields_range(REPLY_MAGIC, self.fields_v1(), offset, output)?)
    }

    /// Commits the complete unsigned reply without aggregating its fields.
    ///
    /// # Errors
    /// Rejects malformed temporal DATA, invalid field widths or overflow.
    pub fn digest_v1(self) -> Result<[u8; 32]> {
        self.encoded_bytes_v1()?;
        hash_fields_v1(REPLY_DOMAIN, REPLY_MAGIC, self.fields_v1())
    }

}

/// Holds the exact final completion comparison packet width.
pub const FINAL_BYTES_V1: usize = 232 +
    crate::domain_ledger::effect_history::CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1;
/// Holds the strict final Root acknowledgement width.
pub const CLOSED_BYTES_V1: usize = 160;
const FINAL_MAGIC: &[u8; 8] = b"AOSAPF01";
const CLOSED_MAGIC: &[u8; 8] = b"AOSAPC01";

/// Borrows actual final native-position and lifecycle receipt comparison DATA.
///
/// Root independently rereads the actual Controller, Session and Source through
/// distinct fresh owners before acknowledging. This packet cannot prove that a
/// child applied or resources activated. Root requires the real Source
/// Completing model with semantic facts; public Terminal/STOPPED is a later
/// client-owned CAS after this acknowledgement and all native posts.
#[derive(Clone, Copy)]
pub struct StorageApplyFinalDataV1<'bytes> {
    /// The same Root nonce from the retained unsigned reply.
    pub root_nonce: [u8; 16],
    /// The same Controller nonce from the original query.
    pub controller_nonce: [u8; 16],
    /// The exact original query commitment.
    pub query_digest: [u8; 32],
    /// The exact complete unsigned reply commitment.
    pub reply_digest: [u8; 32],
    /// The actual final Controller names, NEXT and durable end, as 64 DATA bytes.
    pub controller_native: &'bytes [u8],
    /// The actual final Source names, NEXT and durable end, as 64 DATA bytes.
    pub source_native: &'bytes [u8],
    /// The canonical Applied evidence from the actual retained Effect.
    /// Its Source digest names the actual Completing row; these bytes alone
    /// cannot publish public success or a Source Terminal transition.
    pub lifecycle_receipt: &'bytes [u8],
}

impl<'bytes> StorageApplyFinalDataV1<'bytes> {
    fn validate_v1(self, lane: [u8; 16]) -> Result<()> {
        if self.root_nonce == [0; 16] || self.controller_nonce == [0; 16]
            || self.query_digest == [0; 32] || self.reply_digest == [0; 32]
        { return Err(ApplyRootDataErrorV1::Malformed); }
        require_native_position_data_v1(self.controller_native)?;
        require_native_position_data_v1(self.source_native)?;
        use crate::domain_ledger::effect_history::{
            decode_lifecycle_effect_receipt_v1, LifecycleEffectReceiptDataV1,
        };
        match decode_lifecycle_effect_receipt_v1(self.lifecycle_receipt, lane)
            .map_err(|_| ApplyRootDataErrorV1::Malformed)?
        {
            LifecycleEffectReceiptDataV1::CreateStopped(_) => Ok(()),
            LifecycleEffectReceiptDataV1::Ordinary { .. }
                | LifecycleEffectReceiptDataV1::StopResidual(_) => Err(ApplyRootDataErrorV1::Malformed),
        }
    }

    /// Borrows exact completion framing through the sole lifecycle receipt codec.
    ///
    /// # Errors
    /// Refuses another purpose, nonexact native positions, sentinel identities,
    /// ordinary lifecycle receipts, a different lane or trailing bytes.
    pub fn decode_v1(bytes: &'bytes [u8], lane: [u8; 16]) -> Result<Self> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *FINAL_MAGIC { return Err(ApplyRootDataErrorV1::Malformed); }
        let value = Self {
            root_nonce: input.array()?, controller_nonce: input.array()?,
            query_digest: input.array()?, reply_digest: input.array()?,
            controller_native: input.bytes(64)?, source_native: input.bytes(64)?,
            lifecycle_receipt: input.bytes(crate::domain_ledger::effect_history::
                CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1)?,
        };
        input.finish()?;
        value.validate_v1(lane)?;
        Ok(value)
    }

    /// Copies exact borrowed completion bytes without creating an original.
    ///
    /// # Errors
    /// Refuses the same malformed identities and receipt relations as decoding.
    pub fn encode_v1(self, lane: [u8; 16]) -> Result<[u8; FINAL_BYTES_V1]> {
        self.validate_v1(lane)?;
        let mut bytes = [0; FINAL_BYTES_V1];
        bytes[..8].copy_from_slice(FINAL_MAGIC);
        bytes[8..24].copy_from_slice(&self.root_nonce);
        bytes[24..40].copy_from_slice(&self.controller_nonce);
        bytes[40..72].copy_from_slice(&self.query_digest);
        bytes[72..104].copy_from_slice(&self.reply_digest);
        bytes[104..168].copy_from_slice(self.controller_native);
        bytes[168..232].copy_from_slice(self.source_native);
        bytes[232..].copy_from_slice(self.lifecycle_receipt);
        Ok(bytes)
    }

    /// Commits this exact final packet under its separate purpose domain.
    ///
    /// # Errors
    /// Refuses any malformed native position or lifecycle receipt before hashing.
    pub fn digest_v1(self, lane: [u8; 16]) -> Result<[u8; 32]> {
        Ok(Sha256::new().chain_update(FINAL_DOMAIN).chain_update(self.encode_v1(lane)?)
            .finalize().into())
    }
}

fn require_native_position_data_v1(bytes: &[u8]) -> Result<()> {
    let mut input = reader(bytes);
    crate::domain_ledger::protected_names::ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
        .map_err(|_| ApplyRootDataErrorV1::Malformed)?;
    if input.u64()? == 0 || input.u64()? == 0 { return Err(ApplyRootDataErrorV1::Malformed); }
    input.finish()
}

/// Carries Root's strict final acknowledgement as comparison DATA.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StorageApplyClosedDataV1 {
    /// The same actual Root flight's nonce.
    pub root_nonce: [u8; 16],
    /// The same actual Controller flight's nonce.
    pub controller_nonce: [u8; 16],
    /// The exact original query commitment.
    pub query_digest: [u8; 32],
    /// The exact independently normalized reply commitment.
    pub reply_digest: [u8; 32],
    /// The exact final comparison packet commitment.
    pub final_digest: [u8; 32],
    /// Root's actual completed final paired wall seconds.
    pub observed_wall_seconds: i64,
    /// Root's actual completed final paired BOOTTIME value.
    pub observed_boottime_ns: u64,
    /// The same original minimum cutoff, without renewal.
    pub cutoff_ns: u64,
}

impl StorageApplyClosedDataV1 {
    fn validate_v1(self) -> Result<()> {
        if self.root_nonce == [0; 16] || self.controller_nonce == [0; 16]
            || self.query_digest == [0; 32] || self.reply_digest == [0; 32]
            || self.final_digest == [0; 32] || self.observed_wall_seconds <= 0
            || self.observed_boottime_ns == 0 || self.cutoff_ns <= self.observed_boottime_ns
        { return Err(ApplyRootDataErrorV1::Malformed); }
        Ok(())
    }

    /// Decodes only the exact closed-purpose acknowledgement.
    ///
    /// # Errors
    /// Rejects malformed identities, elapsed cutoffs, wrong purpose or extent.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *CLOSED_MAGIC { return Err(ApplyRootDataErrorV1::Malformed); }
        let value = Self { root_nonce: input.array()?, controller_nonce: input.array()?,
            query_digest: input.array()?, reply_digest: input.array()?, final_digest: input.array()?,
            observed_wall_seconds: input.i64()?, observed_boottime_ns: input.u64()?,
            cutoff_ns: input.u64()? };
        input.finish()?;
        value.validate_v1()?;
        Ok(value)
    }

    /// Encodes strict acknowledgement DATA without granting a terminal state.
    ///
    /// # Errors
    /// Rejects the same malformed identity and clock relations as decoding.
    pub fn encode_v1(self) -> Result<[u8; CLOSED_BYTES_V1]> {
        self.validate_v1()?;
        let mut bytes = [0; CLOSED_BYTES_V1];
        bytes[..8].copy_from_slice(CLOSED_MAGIC);
        bytes[8..24].copy_from_slice(&self.root_nonce);
        bytes[24..40].copy_from_slice(&self.controller_nonce);
        bytes[40..72].copy_from_slice(&self.query_digest);
        bytes[72..104].copy_from_slice(&self.reply_digest);
        bytes[104..136].copy_from_slice(&self.final_digest);
        bytes[136..144].copy_from_slice(&self.observed_wall_seconds.to_be_bytes());
        bytes[144..152].copy_from_slice(&self.observed_boottime_ns.to_be_bytes());
        bytes[152..160].copy_from_slice(&self.cutoff_ns.to_be_bytes());
        Ok(bytes)
    }
}

fn hash_fields_v1<const N: usize>(domain: &[u8], magic: &[u8; 8], fields: [&[u8]; N])
    -> Result<[u8; 32]>
{
    Ok(super::opening::hash_fields(domain, magic, fields)?)
}

fn reader(bytes: &[u8]) -> BoundedReader<'_, ApplyRootDataErrorV1> {
    BoundedReader::new(bytes, |_| ApplyRootDataErrorV1::Extent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission() -> StorageApplyAdmissionDataV1 {
        StorageApplyAdmissionDataV1 {
            root_nonce: [1; 16], controller_nonce: [2; 16], query_digest: [3; 32],
            original_boot: [4; 16], original_boottime_ns: 10, original_cutoff_ns: 90,
            observed_wall_seconds: 20, observed_boottime_ns: 30, cutoff_ns: 80,
            policy_expires_seconds: 40, lease_expires_seconds: 50,
            preparation_expires_boottime_ns: 85,
        }
    }

    #[test]
    fn announcement_is_exact_and_cannot_hide_empty_or_wrong_fixed_fields() {
        let temporal = admission().encode_v1().unwrap();
        let reply = StorageApplyReplyDataV1 {
            admission: &temporal, canonical_plan: b"plan", canonical_statement: b"statement",
        };
        let mut header = [0; 20];
        reply.encode_range_v1(0, &mut header).unwrap();
        assert_eq!(StorageApplyReplyDataV1::declared_encoded_bytes_v1(&header).unwrap(),
            reply.encoded_bytes_v1().unwrap());

        let mut wrong_fixed = header;
        wrong_fixed[8..12].copy_from_slice(&151_u32.to_be_bytes());
        assert!(StorageApplyReplyDataV1::declared_encoded_bytes_v1(&wrong_fixed).is_err());
        let mut empty = header;
        empty[12..16].fill(0);
        assert!(StorageApplyReplyDataV1::declared_encoded_bytes_v1(&empty).is_err());
        assert!(StorageApplyReplyDataV1::declared_encoded_bytes_v1(&header[..19]).is_err());
        let mut extra = header.to_vec();
        extra.push(0);
        assert!(StorageApplyReplyDataV1::declared_encoded_bytes_v1(&extra).is_err());
    }

    #[test]
    fn disjoint_ranges_and_hash_bind_every_reply_byte() {
        let temporal = admission().encode_v1().unwrap();
        let plan = vec![5; 8201];
        let reply = StorageApplyReplyDataV1 {
            admission: &temporal, canonical_plan: &plan, canonical_statement: b"statement",
        };
        let mut complete = vec![0; reply.encoded_bytes_v1().unwrap()];
        reply.encode_range_v1(0, &mut complete).unwrap();
        let mut segmented = vec![0; complete.len()];
        for (index, part) in segmented.chunks_mut(17).enumerate() {
            reply.encode_range_v1(index * 17, part).unwrap();
        }
        assert_eq!(complete, segmented);
        let expected: [u8; 32] = Sha256::new().chain_update(REPLY_DOMAIN)
            .chain_update(&complete).finalize().into();
        assert_eq!(reply.digest_v1().unwrap(), expected);
        let original = reply.digest_v1().unwrap();
        complete[20 + ADMISSION_DATA_BYTES_V1 + 4100] ^= 1;
        assert_ne!(StorageApplyReplyDataV1::decode_v1(&complete).unwrap().digest_v1().unwrap(), original);
        assert!(reply.encode_range_v1(segmented.len(), &mut [0]).is_err());
    }

    #[test]
    fn immutable_deadlines_and_complete_acknowledgements_do_not_renew() {
        let original = admission();
        assert_eq!(StorageApplyAdmissionDataV1::decode_v1(&original.encode_v1().unwrap()).unwrap(), original);
        for changed in [StorageApplyAdmissionDataV1 { cutoff_ns: 91, ..original },
            StorageApplyAdmissionDataV1 { cutoff_ns: 86, ..original },
            StorageApplyAdmissionDataV1 { observed_boottime_ns: 9, ..original },
            StorageApplyAdmissionDataV1 { lease_expires_seconds: 20, ..original }]
        {
            assert!(changed.encode_v1().is_err());
        }
        let closed = StorageApplyClosedDataV1 {
            root_nonce: [1; 16], controller_nonce: [2; 16], query_digest: [3; 32],
            reply_digest: [4; 32], final_digest: [5; 32], observed_wall_seconds: 60,
            observed_boottime_ns: 70, cutoff_ns: 80,
        };
        let bytes = closed.encode_v1().unwrap();
        assert_eq!(StorageApplyClosedDataV1::decode_v1(&bytes).unwrap(), closed);
        assert!(StorageApplyClosedDataV1::decode_v1(&bytes[..CLOSED_BYTES_V1 - 1]).is_err());
        assert!(StorageApplyClosedDataV1 { observed_boottime_ns: 80, ..closed }.encode_v1().is_err());
        assert!(StorageApplyFinalDataV1::decode_v1(&[0; FINAL_BYTES_V1], [1; 16]).is_err());
    }
}
