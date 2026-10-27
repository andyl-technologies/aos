//! Frames the retained Execution no-Apply Root exchange as passive DATA.
//!
//! ```text
//! AOSENQ02 = common fixed112 opening
//! AOSENS02 = preliminary-lease | whole-C-cut | wall | predecessor3 | successor3
//! AOSENR02 = query-digest | Root-read-nonce | unchanged-cutoff
//! AOSENF02 = query-digest | same-whole-C-cut | same-wall | same-predecessors | same-successors
//! AOSENL02 = query-digest | same-Root-read-nonce | canonical-Root-attestation
//! AOSENK02 = query-digest | canonical-Controller-prepare | canonical-Controller-ACK
//! ```
//!
//! These fields neither adopt a Root floor nor establish native completion.
//! The actual Source/C18, Controller writer, Host Session and Root connection
//! remain continuously borrowed through the native programme and its posts.

use super::{opening, super::create_storage_history::{HistoryErrorV1, continuation::framing}};
use crate::host_execution_no_apply::{
    current_lease::{CurrentHostNoApplyLeaseDataV2, MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2},
    closed_controller::{ClosedCreateFailurePrepareDataV2, ControllerCreateFailureAckDataV2,
        CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2, CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2},
    root_attestation::{RootExecutionNoApplyAttestationDataV2, MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2},
};
use crate::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2;

/// Names the distinct Execution opening, preserving the common fixed width.
pub const QUERY_MAGIC_V2: &[u8; 8] = b"AOSENQ02";
/// Holds the common exact opening width.
pub const QUERY_BYTES_V2: usize = opening::QUERY_BYTES;
/// Holds the three-field reply prefix received before admitting its full extent.
pub const REPLY_HEADER_BYTES_V2: usize = 20;
const QUERY_DOMAIN: &[u8] = b"aos.sandbox.root.execution-no-apply.query.v2\0";

/// Holds the actual first-clock and immutable Root programme coordinates as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionNoApplyQueryDataV2 {
    /// Separately paid actual Controller Root-child nonce.
    pub controller_nonce: [u8; 16],
    /// Actual paid Controller cut sample's boot identity.
    pub original_boot: [u8; 16],
    /// That same sample's BOOTTIME coordinate.
    pub original_boottime_ns: u64,
    /// Unchanged original programme deadline.
    pub original_cutoff_ns: u64,
    /// Complete preliminary subject width.
    pub subject_bytes: u64,
    /// Purpose-domain commitment of the actual preliminary subject.
    pub subject_digest: [u8; 32],
    /// Held whole Controller cut's global NEXT.
    pub controller_next: u64,
    /// Held whole Controller cut's durable end.
    pub controller_end: u64,
}

impl ExecutionNoApplyQueryDataV2 {
    fn fields(self) -> opening::QueryFieldsV1 {
        opening::QueryFieldsV1 {
            controller_nonce: self.controller_nonce, original_boot: self.original_boot,
            original_boottime_ns: self.original_boottime_ns, original_cutoff_ns: self.original_cutoff_ns,
            subject_bytes: self.subject_bytes, subject_digest: self.subject_digest,
            controller_next: self.controller_next, controller_end: self.controller_end,
        }
    }

    /// Decodes only this purpose without imposing a new relative deadline.
    ///
    /// # Errors
    /// Refuses wrong purpose, malformed coordinates or trailing bytes.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let f = opening::QueryFieldsV1::decode(bytes, QUERY_MAGIC_V2)?;
        Ok(Self { controller_nonce: f.controller_nonce, original_boot: f.original_boot,
            original_boottime_ns: f.original_boottime_ns, original_cutoff_ns: f.original_cutoff_ns,
            subject_bytes: f.subject_bytes, subject_digest: f.subject_digest,
            controller_next: f.controller_next, controller_end: f.controller_end })
    }

    /// Encodes the unchanged owned programme coordinates as DATA.
    ///
    /// # Errors
    /// Refuses invalid fixed coordinates or an empty subject.
    pub fn encode_v2(self) -> Result<[u8; QUERY_BYTES_V2], HistoryErrorV1> {
        self.fields().encode(QUERY_MAGIC_V2)
    }

    /// Commits the exact opening under the distinct Execution domain.
    ///
    /// # Errors
    /// Refuses invalid fixed coordinates.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.fields().digest(QUERY_MAGIC_V2, QUERY_DOMAIN)
    }
}

// Every finite purpose uses the same borrowed-field parser/range encoder.
macro_rules! frame {
    ($name:ident, $magic:literal, $domain:literal, $count:literal,
        $( $(#[$doc:meta])* $field:ident: $max:expr ),+ $(,)?) => {
        /// Borrows a finite Execution frame without granting native authority.
        #[derive(Clone, Copy)]
        pub struct $name<'held> { $( $(#[$doc])* pub $field: &'held [u8], )+ }

        impl<'held> $name<'held> {
            fn fields(self) -> [&'held [u8]; $count] { [$(self.$field),+] }
            fn maxima() -> [usize; $count] { [$($max),+] }

            /// Measures announced fields before any aggregate allocation.
            ///
            /// # Errors
            /// Refuses another purpose, empty fields, excessive widths or overflow.
            pub fn declared_bytes_v2(header: &[u8]) -> Result<usize, HistoryErrorV1> {
                framing::declared_fields_bytes(header, $magic, Self::maxima())
            }

            /// Decodes exact borrowed framing and canonical nested DATA.
            ///
            /// # Errors
            /// Refuses malformed nested records, field widths or trailing bytes.
            pub fn decode_v2(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
                let [$($field),+] = framing::decode_fields(bytes, $magic, Self::maxima())?;
                let value = Self { $($field),+ };
                value.encoded_bytes_v2()?;
                Ok(value)
            }

            /// Measures the complete checked frame without allocating.
            ///
            /// # Errors
            /// Refuses noncanonical nested DATA, widths or arithmetic overflow.
            pub fn encoded_bytes_v2(self) -> Result<usize, HistoryErrorV1> {
                self.require_fields()?;
                for (field, maximum) in self.fields().into_iter().zip(Self::maxima()) {
                    if field.is_empty() || field.len() > maximum { return Err(HistoryErrorV1::Extent); }
                }
                framing::fields_bytes(self.fields())
            }

            /// Copies a checked range through the existing shared encoder.
            ///
            /// # Errors
            /// Refuses invalid DATA or a range outside the whole frame.
            pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
                self.encoded_bytes_v2()?;
                framing::encode_fields_range($magic, self.fields(), offset, output)
            }

            /// Commits the literal finite frame under its own purpose domain.
            ///
            /// # Errors
            /// Refuses invalid DATA or arithmetic overflow.
            pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
                self.encoded_bytes_v2()?;
                opening::hash_fields($domain, $magic, self.fields())
            }
        }
    };
}

/// Frames the fresh current-capability-authorized Root acquisition exchange.
pub mod acquisition;

frame!(ExecutionNoApplySubjectDataV2, b"AOSENS02", b"aos.sandbox.root.execution-no-apply.subject.v2\0", 5,
    /// Actual posted preliminary42 lease, still backed by the held Host Session.
    preliminary_lease: MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
    /// Whole native Controller cut, never a selected-row substitute.
    controller_cut: 96,
    /// Actual immutable successor wall second.
    wall: 8,
    /// Exact three predecessor record commitments.
    predecessor: 96,
    /// Exact three successor record commitments.
    successor: 96,
);

frame!(ExecutionNoApplyNonceReplyDataV2, b"AOSENR02", b"aos.sandbox.root.execution-no-apply.nonce-reply.v2\0", 3,
    /// Matching original opening commitment.
    query_digest: 32,
    /// Root's actual independently sampled read nonce.
    root_nonce: 32,
    /// Unchanged original mechanical cutoff.
    original_cutoff: 8,
);

frame!(ExecutionNoApplyCurrentDataV2, b"AOSENF02", b"aos.sandbox.root.execution-no-apply.current.v2\0", 5,
    /// Same opening commitment after genuine Host43 completes.
    query_digest: 32,
    /// Same held whole Controller cut.
    controller_cut: 96,
    /// Same immutable successor wall second.
    wall: 8,
    /// Same three predecessor commitments.
    predecessor: 96,
    /// Same three successor commitments.
    successor: 96,
);

frame!(ExecutionNoApplyFloorReplyDataV2, b"AOSENL02", b"aos.sandbox.root.execution-no-apply.floor-reply.v2\0", 3,
    /// Same original opening commitment.
    query_digest: 32,
    /// Same actual Root read nonce authenticated by Host43.
    root_nonce: 32,
    /// Literal canonical signed Root floor packet; detached DATA grants nothing.
    attestation: MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2,
);

frame!(ExecutionNoApplyAcknowledgementDataV2, b"AOSENK02", b"aos.sandbox.root.execution-no-apply.acknowledgement.v2\0", 3,
    /// Same original opening commitment.
    query_digest: 32,
    /// Literal Controller prepare whose native durability Root independently reads.
    controller_prepare: CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2,
    /// Literal ACK whose native Host and Controller posts Root independently reads.
    controller_ack: CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2,
);

fn exact_nonzero(bytes: &[u8], width: usize) -> Result<(), HistoryErrorV1> {
    if bytes.len() != width || bytes.iter().all(|byte| *byte == 0) {
        return Err(HistoryErrorV1::Malformed);
    }
    Ok(())
}

fn require_rows(cut: &[u8], wall: &[u8], predecessor: &[u8], successor: &[u8]) -> Result<(), HistoryErrorV1> {
    RootExecutionNoApplyControllerCutDataV2::decode_canonical(cut).map_err(|_| HistoryErrorV1::Malformed)?;
    if wall.len() != 8 { return Err(HistoryErrorV1::Extent); }
    for rows in [predecessor, successor] {
        if rows.len() != 96 { return Err(HistoryErrorV1::Extent); }
        for digest in rows.chunks_exact(32) { exact_nonzero(digest, 32)?; }
    }
    Ok(())
}

impl ExecutionNoApplySubjectDataV2<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        CurrentHostNoApplyLeaseDataV2::decode_canonical(self.preliminary_lease).map_err(|_| HistoryErrorV1::Malformed)?;
        require_rows(self.controller_cut, self.wall, self.predecessor, self.successor)
    }
}

impl ExecutionNoApplyNonceReplyDataV2<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        exact_nonzero(self.root_nonce, 32)?;
        exact_nonzero(self.original_cutoff, 8)
    }
}

impl ExecutionNoApplyCurrentDataV2<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        require_rows(self.controller_cut, self.wall, self.predecessor, self.successor)
    }
}

impl ExecutionNoApplyFloorReplyDataV2<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        exact_nonzero(self.root_nonce, 32)?;
        let packet = RootExecutionNoApplyAttestationDataV2::decode_canonical(self.attestation)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        if packet.root_read_nonce_v2().as_slice() != self.root_nonce { return Err(HistoryErrorV1::Malformed); }
        Ok(())
    }
}

impl ExecutionNoApplyAcknowledgementDataV2<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        let ack = ControllerCreateFailureAckDataV2::decode_canonical(self.controller_ack)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        let prepare = ClosedCreateFailurePrepareDataV2::decode_canonical(ack.operation.as_bytes(), self.controller_prepare)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        if ack.root_floor != prepare.root_floor || ack.root_sequence != prepare.root_sequence
            || ack.controller_prepare != prepare.digest() || ack.settled_cas != prepare.settled_cas_digest() {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }
}
