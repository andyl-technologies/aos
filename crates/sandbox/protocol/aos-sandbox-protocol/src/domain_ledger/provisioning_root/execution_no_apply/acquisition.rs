//! Frames fresh Root acquisition before any new Host42 or nonce43 exists.
//!
//! ```text
//! AOSANQ02[96] = shared nonce/time/subject opening prefix, without C NEXT/end
//! AOSANS02 = Recover-key | commitment | original-pair48 | D | wall-expiry |
//!            cleanup-nonce32 | Controller-pair48 | cleanup-D | Host-Session |
//!            historical64 | accepted216 | marker448 | original-H | original-T
//! AOSANR02 = query-digest | canonical-signed-Root-acquisition
//! ```
//!
//! Every field is comparison DATA. The genuine Root issuer independently reads
//! current kind3 Recover authority, full C/Host/Source/Root history and its real
//! protected signing credential. This grammar cannot carry a caller-selected
//! current phase, C cut, Root floor, instance or native owner.

use super::*;
use crate::domain_ledger::provisioning_root::finality_recover::{
    CreateFinalityObservationAdmissionDataV1, OBSERVATION_ADMISSION_KEY_BYTES_V1,
};
use crate::host_execution_availability::observation::{
    HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2, HostExecutionAvailabilityObservationV2,
};
use crate::host_execution_no_apply::{
    BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2, BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2,
    BeforeArgumentNoApplySourceDataV2, ClosedBeforeArgumentNoApplyRecordV2,
    recovery_acquisition::{
        MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2, RootNoApplyRecoveryAcquisitionDataV2,
    },
};
use aos_sandbox_model::bounded_codec::BoundedReader;
use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};

/// Names this distinct fresh acquisition opening.
pub const ACQUISITION_QUERY_MAGIC_V2: &[u8; 8] = b"AOSANQ02";
/// Holds the exact opening width with no invented Controller cut.
pub const ACQUISITION_QUERY_BYTES_V2: usize = opening::QUERY_ENVELOPE_BYTES_V2;
/// Holds the borrowed two-field acquisition reply prefix.
pub const ACQUISITION_REPLY_HEADER_BYTES_V2: usize = 16;
/// Holds the canonical explicit raw paired-clock DATA width.
pub const ACQUISITION_RAW_PAIR_BYTES_V2: usize = 48;
/// Gives the exact fourteen-field subject width before receiving its payload.
pub const ACQUISITION_SUBJECT_BYTES_V2: usize = 8
    + 14 * 4
    + OBSERVATION_ADMISSION_KEY_BYTES_V1
    + 32
    + 2 * ACQUISITION_RAW_PAIR_BYTES_V2
    + 3 * 8
    + 32
    + 32
    + HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2
    + BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2
    + BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2
    + 64;
/// Gives the complete maximum signed acquisition reply receiving extent.
pub const MAXIMUM_ACQUISITION_REPLY_BYTES_V2: usize =
    ACQUISITION_REPLY_HEADER_BYTES_V2 + 32 + MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2;

/// Holds only fresh original clock and bounded subject coordinates as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionNoApplyAcquisitionQueryDataV2 {
    /// First sixteen bytes of the genuine fresh Controller cleanup nonce.
    pub controller_nonce: [u8; 16],
    /// Actual fresh Controller original boot identity.
    pub original_boot: [u8; 16],
    /// Actual fresh first native BOOTTIME coordinate.
    pub original_boottime_ns: u64,
    /// Immutable fresh cleanup deadline.
    pub original_cutoff_ns: u64,
    /// Exact finite acquisition subject extent.
    pub subject_bytes: u64,
    /// Purpose-domain commitment of that literal subject.
    pub subject_digest: [u8; 32],
}

impl ExecutionNoApplyAcquisitionQueryDataV2 {
    fn require_shape(self) -> Result<(), HistoryErrorV1> {
        if self.subject_bytes
            != u64::try_from(ACQUISITION_SUBJECT_BYTES_V2).map_err(|_| HistoryErrorV1::Extent)?
        {
            return Err(HistoryErrorV1::Extent);
        }
        Ok(())
    }

    fn envelope(self) -> opening::QueryEnvelopeFieldsV2 {
        opening::QueryEnvelopeFieldsV2 {
            controller_nonce: self.controller_nonce,
            original_boot: self.original_boot,
            original_boottime_ns: self.original_boottime_ns,
            original_cutoff_ns: self.original_cutoff_ns,
            subject_bytes: self.subject_bytes,
            subject_digest: self.subject_digest,
        }
    }

    /// Decodes the exact fresh opening without sampling or renewing authority.
    ///
    /// # Errors
    /// Refuses another purpose, sentinel coordinates or trailing bytes.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let value = opening::QueryEnvelopeFieldsV2::decode(bytes, ACQUISITION_QUERY_MAGIC_V2)?;
        let value = Self {
            controller_nonce: value.controller_nonce,
            original_boot: value.original_boot,
            original_boottime_ns: value.original_boottime_ns,
            original_cutoff_ns: value.original_cutoff_ns,
            subject_bytes: value.subject_bytes,
            subject_digest: value.subject_digest,
        };
        value.require_shape()?;
        Ok(value)
    }

    /// Encodes the exact distinct opening through the shared fixed-prefix recipe.
    ///
    /// # Errors
    /// Refuses invalid fresh coordinates or an empty subject.
    pub fn encode_v2(self) -> Result<[u8; ACQUISITION_QUERY_BYTES_V2], HistoryErrorV1> {
        self.require_shape()?;
        self.envelope().encode(ACQUISITION_QUERY_MAGIC_V2)
    }

    /// Commits the exact opening under its distinct acquisition domain.
    ///
    /// # Errors
    /// Refuses malformed opening coordinates.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.require_shape()?;
        self.envelope().digest(
            ACQUISITION_QUERY_MAGIC_V2,
            b"aos.sandbox.root.execution-no-apply.acquisition-query.v2\0",
        )
    }
}

frame!(ExecutionNoApplyAcquisitionSubjectDataV2, b"AOSANS02",
    b"aos.sandbox.root.execution-no-apply.acquisition-subject.v2\0", 14,
    /// Selects the existing protected Recover admission row by its canonical key.
    admission_key: OBSERVATION_ADMISSION_KEY_BYTES_V1,
    /// Commits that exact protected row using its sole existing codec.
    admission: 32,
    /// Explicit provenance16/boot16/wall8/BOOTTIME8 of the admitted Recover.
    recover_original: ACQUISITION_RAW_PAIR_BYTES_V2,
    /// Immutable admitted Recover deadline, never an old64 renewal.
    recover_cutoff: 8,
    /// Exclusive actual new authority wall expiry.
    recover_wall_expiry: 8,
    /// Fresh actual Controller cleanup nonce from its retained native original.
    controller_nonce: 32,
    /// Fresh actual Controller first paired native observation.
    controller_first: ACQUISITION_RAW_PAIR_BYTES_V2,
    /// Immutable cleanup deadline no later than the admitted Recover deadline.
    cleanup_cutoff: 8,
    /// Actual newly negotiated Host Session, retained by the same SDK original.
    host_session: 32,
    /// Original bound64 observation, retained strictly as authenticated history.
    historical_availability: HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2,
    /// Original accepted Create identity, retained strictly as history.
    accepted_source: BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2,
    /// Actual original durable39 fence, retained strictly as history.
    marker: BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2,
    /// Exact historical terminal group commitment H.
    terminal_archive: 32,
    /// Exact historical signed39 packet commitment T.
    signed_terminal: 32,
);

frame!(ExecutionNoApplyAcquisitionReplyDataV2, b"AOSANR02",
    b"aos.sandbox.root.execution-no-apply.acquisition-reply.v2\0", 2,
    /// Commits this exact opening and its subject association.
    query_digest: 32,
    /// Canonical dedicated-key signed acquisition; native signature checking remains required.
    acquisition: MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2,
);

impl ExecutionNoApplyAcquisitionSubjectDataV2<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        CreateFinalityObservationAdmissionDataV1::require_key_v1(self.admission_key)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        for field in [
            self.admission,
            self.controller_nonce,
            self.host_session,
            self.terminal_archive,
            self.signed_terminal,
        ] {
            exact_nonzero(field, 32)?;
        }
        let recover = decode_acquisition_raw_pair_data_v2(self.recover_original)?;
        let first = decode_acquisition_raw_pair_data_v2(self.controller_first)?;
        let recover_cutoff = integer(self.recover_cutoff)?;
        let cutoff = integer(self.cleanup_cutoff)?;
        let expiry = i64::from_be_bytes(
            self.recover_wall_expiry
                .try_into()
                .map_err(|_| HistoryErrorV1::Extent)?,
        );
        if recover.boottime_nanoseconds() == 0
            || first.host_boot_id() != recover.host_boot_id()
            || first.boottime_nanoseconds() < recover.boottime_nanoseconds()
            || first.boottime_nanoseconds() >= cutoff
            || cutoff > recover_cutoff
            || expiry <= recover.wall_seconds()
        {
            return Err(HistoryErrorV1::Malformed);
        }
        // Canonical nested DATA is necessary but supplies no cross-record
        // native authority. The genuine Root issuer checks every historical join.
        HostExecutionAvailabilityObservationV2::decode_canonical(self.historical_availability)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        BeforeArgumentNoApplySourceDataV2::decode_canonical(self.accepted_source)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(self.marker)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        Ok(())
    }
}

impl ExecutionNoApplyAcquisitionReplyDataV2<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(self.acquisition)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        Ok(())
    }
}

fn integer(bytes: &[u8]) -> Result<u64, HistoryErrorV1> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| HistoryErrorV1::Extent)?,
    ))
}

/// Encodes raw clock DATA without creating native clock provenance.
#[must_use]
pub fn encode_acquisition_raw_pair_data_v2(
    sample: RawPairedClockSample,
) -> [u8; ACQUISITION_RAW_PAIR_BYTES_V2] {
    let mut bytes = [0; ACQUISITION_RAW_PAIR_BYTES_V2];
    bytes[..16].copy_from_slice(&sample.provenance().as_bytes());
    bytes[16..32].copy_from_slice(&sample.host_boot_id());
    bytes[32..40].copy_from_slice(&sample.wall_seconds().to_be_bytes());
    bytes[40..48].copy_from_slice(&sample.boottime_nanoseconds().to_be_bytes());
    bytes
}

/// Decodes explicit raw clock DATA without authenticating its reader or sampling.
///
/// # Errors
/// Refuses sentinel provenance/boot identities, wrong width or trailing bytes.
pub fn decode_acquisition_raw_pair_data_v2(
    bytes: &[u8],
) -> Result<RawPairedClockSample, HistoryErrorV1> {
    let mut input = BoundedReader::new(bytes, |_| HistoryErrorV1::Extent);
    let provenance =
        RawClockProvenance::new_untrusted(input.array()?).map_err(|_| HistoryErrorV1::Malformed)?;
    let sample =
        RawPairedClockSample::new_untrusted(provenance, input.array()?, input.i64()?, input.u64()?)
            .map_err(|_| HistoryErrorV1::Malformed)?;
    input.finish()?;
    Ok(sample)
}
