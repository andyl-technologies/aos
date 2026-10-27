//! Frames the fresh accepted Start's Root resource and Host launch flight.
//!
//! ```text
//! query = AOSHLQ01 | nonce16 | firstNativeBoot16 | firstNativeBOOTTIME8 |
//!         unchangedCutoff8 | subjectLength8 | subjectDigest32 | Cnext8 | Cend8
//! subject = AOSHLS01 | fourteen:u32be lengths | StartOp16 | purpose1 |
//!           deadlineFreeRequest | renewalClaim | freshLease | leaseSignature |
//!           leaseReceipt | receiptSignature | acceptedStartOperationV3 |
//!           ReadyB | PrepareRequest | PrepareOutcome | Root6 | currentCAccount
//! ```
//!
//! Historical Create input bytes never supply Start's clock or an operation
//! permit. Root independently authenticates the accepted Start and Source first
//! origin using its actual current readers. Resource and final launch plans
//! require their own closed stages on the retained socket and original horizon.

pub mod completion;

use crate::domain_ledger::create_storage_history::{HistoryErrorV1,
    continuation::framing, outcome::ROOT_CLOSED_RECEIPT_BYTES_V1};
use crate::domain_ledger::{operation::OPERATION_RECORD_V3_BYTES,
    resource_bank::ACCOUNT_HEAD_BYTES_V1};
use aos_sandbox_broker_session_protocol::projection::{
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES};

/// Identifies only the separately funded accepted Start/Host Root opening.
pub const QUERY_MAGIC_V1: &[u8; 8] = b"AOSHLQ01";
/// Holds the complete fixed Root opening width.
pub const QUERY_BYTES_V1: usize = super::opening::QUERY_BYTES;
const QUERY_DOMAIN: &[u8] = b"aos.sandbox.root.host-launch.query.v1\0";
const SUBJECT_MAGIC: &[u8; 8] = b"AOSHLS01";
const SUBJECT_DOMAIN: &[u8] = b"aos.sandbox.root.host-launch.subject.v1\0";
const REPLY_MAGIC: &[u8;8] = b"AOSHLR01";
const REPLY_DOMAIN: &[u8] = b"aos.sandbox.root.host-launch.reply.v1\0";
const ADMISSION_MAGIC: &[u8;8] = b"AOSHLT01";
/// Holds the exact purpose's original temporal comparison width.
pub const ADMISSION_BYTES_V1:usize=152;
/// Holds the strict three-field reply announcement width.
pub const REPLY_HEADER_BYTES_V1:usize=20;

/// Selects one closed, independently completed Root child of the same Start.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
#[repr(u8)]
pub enum HostResourcePurposeDataV1 {
    /// Authorizes only exact sealed Network Prepare63.
    NetworkPrepare=1,
    /// Authorizes only exact Storage guest-root publication31.
    StorageGuestRoot=2,
    /// Authorizes only exact empty Mount namespace materialization62.
    MountNamespace=3,
    /// Authorizes final Host launch plus its exact Guardian companion.
    HostLaunch=4,
}

impl HostResourcePurposeDataV1 {
    /// Parses a closed resource selector without granting that purpose.
    ///
    /// # Errors
    /// Refuses every unassigned ordinal.
    pub fn decode_v1(code:u8)->Result<Self,HistoryErrorV1> {
        match code {1=>Ok(Self::NetworkPrepare),2=>Ok(Self::StorageGuestRoot),
            3=>Ok(Self::MountNamespace),4=>Ok(Self::HostLaunch),_=>Err(HistoryErrorV1::Malformed)}
    }
}

/// Carries current-C and original accepted Start comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostLaunchQueryDataV1 {
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

impl HostLaunchQueryDataV1 {
    /// Decodes exact fixed Host opening DATA without allocating.
    ///
    /// # Errors
    /// Refuses another purpose, sentinels, invalid times or trailing bytes.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let value = super::opening::QueryFieldsV1::decode(bytes, QUERY_MAGIC_V1)?;
        Ok(Self { controller_nonce: value.controller_nonce, original_boot: value.original_boot, original_boottime_ns: value.original_boottime_ns, original_cutoff_ns: value.original_cutoff_ns, subject_bytes: value.subject_bytes, subject_digest: value.subject_digest, controller_next: value.controller_next, controller_end: value.controller_end })
    }

    fn fields_v1(self) -> super::opening::QueryFieldsV1 {
        let Self { controller_nonce, original_boot, original_boottime_ns, original_cutoff_ns, subject_bytes, subject_digest, controller_next, controller_end } = self;
        super::opening::QueryFieldsV1 { controller_nonce, original_boot, original_boottime_ns, original_cutoff_ns, subject_bytes, subject_digest, controller_next, controller_end }
    }

    /// Encodes the same checked fixed Host opening DATA.
    ///
    /// # Errors
    /// Refuses invalid original identity, time or extent fields.
    pub fn encode_v1(self) -> Result<[u8; QUERY_BYTES_V1], HistoryErrorV1> {
        self.fields_v1().encode(QUERY_MAGIC_V1)
    }

    /// Commits the whole Host query, including Start's unchanged horizon.
    ///
    /// # Errors
    /// Refuses invalid fields before hashing.
    pub fn digest_v1(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.fields_v1().digest(QUERY_MAGIC_V1, QUERY_DOMAIN)
    }
}

/// Borrows genuine historical inputs and the actual accepted Start C record.
#[derive(Clone, Copy)]
pub struct HostLaunchSubjectDataV1<'held> {
    /// The same actual public Start operation's key bytes.
    pub start_operation: &'held [u8],
    /// The closed child purpose's exact one-byte encoding.
    pub purpose: &'held [u8],
    /// The exact canonical deadline-free resource request body.
    pub request_body: &'held [u8],
    /// The actual verified fresh renewal claim.
    pub ownership_claim: &'held [u8],
    /// The actual fresh authority-signed lease body.
    pub ownership_lease: &'held [u8],
    /// Its actual detached authority signature.
    pub ownership_signature: &'held [u8],
    /// Its actual signed transaction receipt.
    pub ownership_receipt: &'held [u8],
    /// Its actual detached receipt signature.
    pub ownership_receipt_signature: &'held [u8],
    /// The exact current accepted public Start Operation V3 bytes.
    pub accepted_start: &'held [u8],
    /// The original complete Ready B framing and signed ownership lease.
    pub ready: &'held [u8],
    /// The authenticated original Prepare request packet.
    pub prepare_request: &'held [u8],
    /// The committed authenticated original Prepare outcome packet.
    pub prepare_outcome: &'held [u8],
    /// The permanently sealed original Root6 native receipt.
    pub root_closed: &'held [u8],
    /// The actual current baseline C account head, never an old C23 payer.
    pub controller_account: &'held [u8],
}

impl<'held> HostLaunchSubjectDataV1<'held> {
    fn fields(self) -> [&'held [u8]; 14] {
        [self.start_operation,self.purpose,self.request_body,self.ownership_claim,
            self.ownership_lease,self.ownership_signature,self.ownership_receipt,
            self.ownership_receipt_signature,self.accepted_start,self.ready,self.prepare_request,
            self.prepare_outcome,self.root_closed,self.controller_account]
    }

    fn maxima() -> [usize;14] {
        use aos_sandbox_ownership_protocol::{CLAIM_BYTES,MAXIMUM_LEASE_BYTES,
            MAXIMUM_SIGNATURE_BYTES,MAXIMUM_RECEIPT_BYTES};
        [16,1,AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES,CLAIM_BYTES,MAXIMUM_LEASE_BYTES,
            MAXIMUM_SIGNATURE_BYTES,MAXIMUM_RECEIPT_BYTES,MAXIMUM_SIGNATURE_BYTES,
            OPERATION_RECORD_V3_BYTES,u32::MAX as usize,AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES,
            AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,ROOT_CLOSED_RECEIPT_BYTES_V1,ACCOUNT_HEAD_BYTES_V1]
    }

    /// Decodes borrowed fields through the sole common finite framing engine.
    ///
    /// # Errors
    /// Refuses wrong purpose, empty fields, invalid extents or trailing bytes.
    pub fn decode_v1(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
        let [start_operation,purpose,request_body,ownership_claim,ownership_lease,
            ownership_signature,ownership_receipt,ownership_receipt_signature,
            accepted_start,ready,prepare_request,prepare_outcome,root_closed,controller_account] =
            framing::decode_fields(bytes,SUBJECT_MAGIC,Self::maxima())?;
        let value=Self {start_operation,purpose,request_body,ownership_claim,ownership_lease,
            ownership_signature,ownership_receipt,ownership_receipt_signature,
            accepted_start,ready,prepare_request,prepare_outcome,root_closed,controller_account};
        value.encoded_bytes_v1()?;
        Ok(value)
    }

    /// Measures the complete encoding before any aggregate allocation.
    ///
    /// # Errors
    /// Refuses wrong fixed widths, exceeded nested caps, empty fields or overflow.
    pub fn encoded_bytes_v1(self) -> Result<usize, HistoryErrorV1> {
        if self.start_operation.len()!=16 || self.start_operation==[0;16]
            || self.purpose.len()!=1 || HostResourcePurposeDataV1::decode_v1(self.purpose[0]).is_err()
            || self.ownership_claim.len()!=aos_sandbox_ownership_protocol::CLAIM_BYTES
            || self.accepted_start.len()!=OPERATION_RECORD_V3_BYTES
            || self.root_closed.len()!=ROOT_CLOSED_RECEIPT_BYTES_V1
            || self.controller_account.len()!=ACCOUNT_HEAD_BYTES_V1 {
            return Err(HistoryErrorV1::Extent);
        }
        for (field,maximum) in self.fields().into_iter().zip(Self::maxima()) {
            if field.is_empty() || field.len()>maximum {return Err(HistoryErrorV1::Extent);}
        }
        framing::fields_bytes(self.fields())
    }

    /// Copies a checked bounded range from the same borrowed originals.
    ///
    /// # Errors
    /// Refuses invalid framing or a range outside the exact complete encoding.
    pub fn encode_range_v1(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes_v1()?;
        framing::encode_fields_range(SUBJECT_MAGIC, self.fields(), offset, output)
    }

    /// Hashes exact canonical framing without aggregating historical packets.
    ///
    /// # Errors
    /// Refuses malformed fields or overflow before hashing.
    pub fn digest_v1(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.encoded_bytes_v1()?;
        super::opening::hash_fields(SUBJECT_DOMAIN, SUBJECT_MAGIC, self.fields())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_query_cannot_be_adopted_as_apply_or_renew_its_cutoff() {
        let value = HostLaunchQueryDataV1 {controller_nonce:[1;16], original_boot:[2;16],
            original_boottime_ns:10, original_cutoff_ns:90, subject_bytes:1,
            subject_digest:[3;32], controller_next:1, controller_end:1};
        let encoded = value.encode_v1().unwrap();
        assert_eq!(HostLaunchQueryDataV1::decode_v1(&encoded).unwrap(),value);
        assert!(super::super::storage_apply::StorageApplyQueryDataV1::decode_v1(&encoded).is_err());
        let mut invalid=value;
        invalid.original_cutoff_ns=10;
        assert!(invalid.encode_v1().is_err());
    }
}

/// Carries Root's actual original Start and current authority temporal DATA.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct HostResourceAdmissionDataV1 {
    /// The new actual Root child nonce.
    pub root_nonce:[u8;16],
    /// The matching actual Controller child nonce.
    pub controller_nonce:[u8;16],
    /// The exact complete opening query commitment.
    pub query_digest:[u8;32],
    /// The unchanged first native Start boot identity.
    pub original_boot:[u8;16],
    /// The unchanged first native Start BOOTTIME coordinate.
    pub original_boottime_ns:u64,
    /// The unchanged absolute Start cutoff.
    pub original_cutoff_ns:u64,
    /// Root's actual independently sampled wall time.
    pub observed_wall_seconds:i64,
    /// Root's actual independently sampled BOOTTIME.
    pub observed_boottime_ns:u64,
    /// The minimum original/accepted/fresh-policy/fresh-lease child cutoff.
    pub cutoff_ns:u64,
    /// The freshly verified signed policy expiry.
    pub policy_expires_seconds:i64,
    /// The actual freshly verified renewal lease expiry.
    pub lease_expires_seconds:i64,
    /// The immutable accepted Start's absolute wall expiry.
    pub accepted_expires_seconds:i64,
}

impl HostResourceAdmissionDataV1 {
    fn fields_v2(self) -> super::opening::TemporalAdmissionFieldsV2<3> {
        super::opening::TemporalAdmissionFieldsV2 {
            root_nonce: self.root_nonce, controller_nonce: self.controller_nonce,
            query_digest: self.query_digest, original_boot: self.original_boot,
            original_boottime_ns: self.original_boottime_ns,
            original_cutoff_ns: self.original_cutoff_ns,
            observed_wall_seconds: self.observed_wall_seconds,
            observed_boottime_ns: self.observed_boottime_ns, cutoff_ns: self.cutoff_ns,
            authority_expiries: [self.policy_expires_seconds, self.lease_expires_seconds,
                self.accepted_expires_seconds],
        }
    }

    /// Decodes one complete fixed temporal DATA record without adopting it.
    ///
    /// # Errors
    /// Refuses wrong magic, invalid original-time relations or trailing bytes.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let value = super::opening::TemporalAdmissionFieldsV2::<3>::decode(bytes, ADMISSION_MAGIC)?;
        Ok(Self {
            root_nonce: value.root_nonce, controller_nonce: value.controller_nonce,
            query_digest: value.query_digest, original_boot: value.original_boot,
            original_boottime_ns: value.original_boottime_ns,
            original_cutoff_ns: value.original_cutoff_ns,
            observed_wall_seconds: value.observed_wall_seconds,
            observed_boottime_ns: value.observed_boottime_ns, cutoff_ns: value.cutoff_ns,
            policy_expires_seconds: value.authority_expiries[0],
            lease_expires_seconds: value.authority_expiries[1],
            accepted_expires_seconds: value.authority_expiries[2],
        })
    }

    /// Encodes the same checked fixed temporal fields as inert DATA.
    ///
    /// # Errors
    /// Refuses invalid identity or original/fresh authority expiry relations.
    pub fn encode_v1(self) -> Result<[u8; ADMISSION_BYTES_V1], HistoryErrorV1> {
        self.fields_v2().encode(ADMISSION_MAGIC)
    }
}

/// Borrows one unsigned resource plan/statement from the genuine Root child.
#[derive(Clone,Copy)]
pub struct HostResourceReplyDataV1<'held> {
    /// The complete fixed Root temporal comparison DATA.
    pub admission:&'held[u8],
    /// The exact independently normalized unsigned canonical plan.
    pub canonical_plan:&'held[u8],
    /// The exact corresponding canonical signing statement.
    pub canonical_statement:&'held[u8],
}

impl<'held> HostResourceReplyDataV1<'held> {
    fn fields(self)->[&'held[u8];3] {[self.admission,self.canonical_plan,self.canonical_statement]}
    fn maxima()->[usize;3] {[ADMISSION_BYTES_V1,
        u32::MAX as usize,
        u32::MAX as usize]}

    /// Measures only the announced complete reply before receiving allocation.
    ///
    /// # Errors
    /// Refuses wrong purpose, empty/oversized fields or malformed announcement.
    pub fn declared_bytes_v1(header:&[u8])->Result<usize,HistoryErrorV1> {
        let width=framing::declared_fields_bytes(header,REPLY_MAGIC,Self::maxima())?;
        if header.get(8..12)!=Some((ADMISSION_BYTES_V1 as u32).to_be_bytes().as_slice()) {
            return Err(HistoryErrorV1::Extent);
        }
        Ok(width)
    }

    /// Decodes exact borrowed reply framing without constructing authority.
    ///
    /// # Errors
    /// Refuses wrong purpose, empty/oversized fields, temporal width or trailing bytes.
    pub fn decode_v1(bytes:&'held[u8])->Result<Self,HistoryErrorV1> {
        let [admission,canonical_plan,canonical_statement]=framing::decode_fields(bytes,REPLY_MAGIC,Self::maxima())?;
        let value=Self {admission,canonical_plan,canonical_statement};value.encoded_bytes_v1()?;Ok(value)
    }

    /// Measures the whole reply without creating an allocation or permission.
    ///
    /// # Errors
    /// Refuses an invalid fixed temporal width or exceeded nested cap.
    pub fn encoded_bytes_v1(self)->Result<usize,HistoryErrorV1> {
        HostResourceAdmissionDataV1::decode_v1(self.admission)?;
        for (field,maximum) in self.fields().into_iter().zip(Self::maxima()) {
            if field.is_empty() || field.len()>maximum {return Err(HistoryErrorV1::Extent);}
        }
        framing::fields_bytes(self.fields())
    }

    /// Copies a checked bounded range from the same exact borrowed reply.
    ///
    /// # Errors
    /// Refuses malformed framing or an out-of-range copy.
    pub fn encode_range_v1(self,offset:usize,output:&mut[u8])->Result<(),HistoryErrorV1> {
        self.encoded_bytes_v1()?;framing::encode_fields_range(REPLY_MAGIC,self.fields(),offset,output)
    }

    /// Commits exact reply framing under its own closed resource domain.
    ///
    /// # Errors
    /// Refuses invalid nested widths or overflow before hashing.
    pub fn digest_v1(self)->Result<[u8;32],HistoryErrorV1> {
        self.encoded_bytes_v1()?;super::opening::hash_fields(REPLY_DOMAIN,REPLY_MAGIC,self.fields())
    }
}
