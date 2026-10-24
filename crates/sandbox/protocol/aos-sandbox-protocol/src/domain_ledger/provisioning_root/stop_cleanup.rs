//! Frames the held Stop cleanup exchange without issuing native authority.
//!
//! ```text
//! AOSHSQ02[96] = shared nonce/clock/deadline/subject opening
//! AOSHSS02 = Recover reference | fresh Source22 clock/D/parent | fresh Host3
//! AOSHSP02 = query | (AOSHSE02 effect or AOSHSO02 observation)
//! AOSHSE02 = query | subject456 | body | plan | statement | Root clock/expiry/D
//! AOSHSO02 = query | observation tag | completed V7/648 | Root clock/expiry/D
//! AOSHSG02 = query | decision | ordinary Controller signature
//! AOSHSD02 = query | observation decision (no signature)
//! AOSHSF02 = query | final Host3 request/Session/request/outcome/body commitments
//! AOSHSR02 = query | decision | final Host3 outcome commitment | unchanged D
//! ```
//!
//! The same actual Source22, Root connection and Host Session remain held.
//! A decoded frame neither reconstructs an old Stop owner nor establishes a
//! signature, native absence, Source disposition or Root completion.

use super::execution_no_apply::acquisition::{
    ACQUISITION_RAW_PAIR_BYTES_V2, decode_acquisition_raw_pair_data_v2,
};
use super::finality_recover::{
    CreateFinalityObservationAdmissionDataV1, OBSERVATION_ADMISSION_KEY_BYTES_V1,
};
use super::opening;
use crate::domain_ledger::create_storage_history::{HistoryErrorV1, continuation::framing};
use crate::host_stop_cleanup::{
    HOST_STOP_CLEANUP_SUBJECT_BYTES_V1, HostStopCleanupSubjectDataV1,
    MAXIMUM_CANONICAL_HOST_STOP_CLEANUP_BODY_BYTES_V1,
};
use crate::root_policy_completion::{
    StopCleanupObservationDataV1, stop_cleanup_observation_decision_digest_v1,
};
use aos_sandbox_model::RawPairedClockSample;

/// Names the distinct finite Stop cleanup opening.
pub const QUERY_MAGIC_V1: &[u8; 8] = b"AOSHSQ02";
/// Gives the shared exact opening width, with no caller-selected C cut.
pub const QUERY_BYTES_V1: usize = opening::QUERY_ENVELOPE_BYTES_V2;
/// Gives the complete fixed fourteen-field subject extent.
pub const SUBJECT_BYTES_V1: usize = 8
    + 14 * 4
    + OBSERVATION_ADMISSION_KEY_BYTES_V1
    + 32
    + 48
    + 8
    + 8
    + 16
    + 48
    + 8
    + 32
    + 16
    + 32
    + 32
    + 32
    + 32;
/// Gives the common two-field reply header received before allocating its body.
pub const REPLY_HEADER_BYTES_V1: usize = 16;
/// Gives the exact header of the same comparison frame in either direction.
pub const DECISION_HEADER_BYTES_V1: usize = 8 + 2 * 4;
/// Gives Root's exact comparison ACK extent, without a disposition claim.
pub const DECISION_BYTES_V1: usize = DECISION_HEADER_BYTES_V1 + 32 + 32;
/// Gives the exact four-field final receipt header.
pub const RECEIPT_HEADER_BYTES_V1: usize = 24;
/// Gives the complete fixed final receipt extent.
pub const RECEIPT_BYTES_V1: usize = RECEIPT_HEADER_BYTES_V1 + 32 + 32 + 32 + 8;

/// Bounds the same borrowed range encoder's hash scratch and state before use.
///
/// This pure supplier creates no receiving authority or financial owner.
/// Returns `None` on checked arithmetic overflow in the common format engine.
#[must_use]
pub fn stop_cleanup_digest_receiving_bytes_v1() -> Option<usize> {
    framing::hash_fields_receiving_bytes()
}

/// Holds only the actual fresh Source22 opening coordinates as comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StopCleanupQueryDataV1 {
    /// Actual fresh cleanup request ID, rather than the old Stop request.
    pub controller_nonce: [u8; 16],
    /// Actual fresh first sample's boot identity.
    pub original_boot: [u8; 16],
    /// Actual fresh first sample's BOOTTIME coordinate.
    pub original_boottime_ns: u64,
    /// Immutable fresh Source22 deadline.
    pub original_cutoff_ns: u64,
    /// Exact finite subject extent.
    pub subject_bytes: u64,
    /// Purpose-domain commitment of that exact subject.
    pub subject_digest: [u8; 32],
}

impl StopCleanupQueryDataV1 {
    fn fields(self) -> Result<opening::QueryEnvelopeFieldsV2, HistoryErrorV1> {
        if self.subject_bytes
            != u64::try_from(SUBJECT_BYTES_V1).map_err(|_| HistoryErrorV1::Extent)?
        {
            return Err(HistoryErrorV1::Extent);
        }
        Ok(opening::QueryEnvelopeFieldsV2 {
            controller_nonce: self.controller_nonce,
            original_boot: self.original_boot,
            original_boottime_ns: self.original_boottime_ns,
            original_cutoff_ns: self.original_cutoff_ns,
            subject_bytes: self.subject_bytes,
            subject_digest: self.subject_digest,
        })
    }

    /// Decodes only the exact finite opening without renewing its deadline.
    ///
    /// # Errors
    /// Refuses another purpose, malformed coordinates, width or trailing bytes.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let fields = opening::QueryEnvelopeFieldsV2::decode(bytes, QUERY_MAGIC_V1)?;
        let value = Self {
            controller_nonce: fields.controller_nonce,
            original_boot: fields.original_boot,
            original_boottime_ns: fields.original_boottime_ns,
            original_cutoff_ns: fields.original_cutoff_ns,
            subject_bytes: fields.subject_bytes,
            subject_digest: fields.subject_digest,
        };
        value.fields()?;
        Ok(value)
    }

    /// Encodes the same fixed opening through the shared common recipe.
    ///
    /// # Errors
    /// Refuses sentinel coordinates or another subject width.
    pub fn encode_v1(self) -> Result<[u8; QUERY_BYTES_V1], HistoryErrorV1> {
        self.fields()?.encode(QUERY_MAGIC_V1)
    }

    /// Commits the exact opening under the finite Stop cleanup domain.
    ///
    /// # Errors
    /// Refuses malformed opening coordinates.
    pub fn digest_v1(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.fields()?
            .digest(QUERY_MAGIC_V1, b"aos.sandbox.root.stop-cleanup.query.v1\0")
    }
}

// All decoding, integer lengths, range copying and hashing use the existing
// borrowed-field engine; these wrappers select only the finite purpose grammar.
macro_rules! frame {
    ($name:ident, $magic:literal, $domain:literal, $count:literal,
        $( $(#[$doc:meta])* $field:ident: $max:expr ),+ $(,)?) => {
        /// Borrows one finite Stop frame as nonissuing comparison DATA.
        #[derive(Clone, Copy)]
        pub struct $name<'held> { $( $(#[$doc])* pub $field: &'held [u8], )+ }

        impl<'held> $name<'held> {
            fn fields(self) -> [&'held [u8]; $count] { [$(self.$field),+] }
            fn maxima() -> [usize; $count] { [$($max),+] }

            /// Measures the announced extent before any aggregate allocation.
            ///
            /// # Errors
            /// Refuses another purpose, empty/oversized fields or overflow.
            pub fn declared_bytes_v1(header: &[u8]) -> Result<usize, HistoryErrorV1> {
                framing::declared_fields_bytes(header, $magic, Self::maxima())
            }

            /// Decodes exact borrowed framing and its finite nested DATA.
            ///
            /// # Errors
            /// Refuses wrong widths, malformed nested DATA or trailing bytes.
            pub fn decode_v1(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
                let [$($field),+] = framing::decode_fields(bytes, $magic, Self::maxima())?;
                let value = Self { $($field),+ };
                value.encoded_bytes_v1()?;
                Ok(value)
            }

            /// Measures the checked complete frame without allocating.
            ///
            /// # Errors
            /// Refuses malformed DATA, exceeded bounds or integer overflow.
            pub fn encoded_bytes_v1(self) -> Result<usize, HistoryErrorV1> {
                self.require_fields()?;
                for (field, maximum) in self.fields().into_iter().zip(Self::maxima()) {
                    if field.is_empty() || field.len() > maximum { return Err(HistoryErrorV1::Extent); }
                }
                framing::fields_bytes(self.fields())
            }

            /// Copies one checked range through the common borrowed encoder.
            ///
            /// # Errors
            /// Refuses invalid DATA or a range outside the complete frame.
            pub fn encode_range_v1(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
                self.encoded_bytes_v1()?;
                framing::encode_fields_range($magic, self.fields(), offset, output)
            }

            /// Commits the literal frame under its finite purpose domain.
            ///
            /// # Errors
            /// Refuses invalid DATA or arithmetic overflow.
            pub fn digest_v1(self) -> Result<[u8; 32], HistoryErrorV1> {
                self.encoded_bytes_v1()?;
                opening::hash_fields($domain, $magic, self.fields())
            }
        }
    };
}

frame!(StopCleanupSubjectDataV1, b"AOSHSS02", b"aos.sandbox.root.stop-cleanup.subject.v1\0", 14,
    /// Selects the actual protected Recover admission row.
    admission_key: OBSERVATION_ADMISSION_KEY_BYTES_V1,
    /// Commits the actual row using the sole admission commitment recipe.
    admission: 32,
    /// Original admitted Recover provenance/boot/wall/BOOTTIME DATA.
    recover_original: ACQUISITION_RAW_PAIR_BYTES_V2,
    /// Immutable admitted Recover deadline.
    recover_cutoff: 8,
    /// Exclusive admitted current-capability wall expiry.
    recover_wall_expiry: 8,
    /// Actual fresh cleanup request ID.
    cleanup: 16,
    /// Actual Source22 first paired sample, distinct from Recover's pair.
    controller_first: ACQUISITION_RAW_PAIR_BYTES_V2,
    /// Immutable fresh Source22 deadline.
    cleanup_cutoff: 8,
    /// Actual fresh Source22 publication parent commitment.
    source_parent: 32,
    /// Actual fresh Host3 request ID from the same Source22 SDK owner.
    host_query: 16,
    /// Actual fresh Host Session, never the retired17 Session.
    host_session: 32,
    /// Exact signed Host3 request packet SHA256.
    host_request: 32,
    /// Exact canonical signed Host3 outcome packet SHA256.
    host_outcome: 32,
    /// Exact Host3 response body SHA256.
    host_body: 32,
);

frame!(StopCleanupEffectDataV1, b"AOSHSE02", b"aos.sandbox.root.stop-cleanup.effect.v1\0", 8,
    /// Original opening commitment.
    query_digest: 32,
    /// Exact current normalized cleanup subject.
    subject: HOST_STOP_CLEANUP_SUBJECT_BYTES_V1,
    /// Exact canonical live Stop request body supplied by the same normalizer.
    request_body: MAXIMUM_CANONICAL_HOST_STOP_CLEANUP_BODY_BYTES_V1,
    /// Ordinary unsigned authorization plan; genuine preparation compares it.
    canonical_plan: u32::MAX as usize,
    /// Exact ordinary signing statement; never a Root private-key request.
    canonical_statement: u32::MAX as usize,
    /// Actual Root paired sample used to prepare the plan.
    root_sample: ACQUISITION_RAW_PAIR_BYTES_V2,
    /// Exclusive current Root policy wall expiry.
    policy_expiry: 8,
    /// Narrowed deadline bounded by the unchanged original Source22 D.
    cutoff: 8,
);

frame!(StopCleanupReplyDataV1, b"AOSHSP02", b"aos.sandbox.root.stop-cleanup.reply.v1\0", 2,
    /// Original opening commitment, repeated strictly in the nested decision.
    query_digest: 32,
    /// Sole effect or observation frame; no unknown future branch is accepted.
    decision_frame: u32::MAX as usize,
);

/// Selects a checked effect or completed observation without issuing a grant.
#[derive(Clone, Copy)]
pub enum StopCleanupDecisionDataV1<'held> {
    /// Carries an ordinary unsigned Controller plan requiring genuine signing.
    Effect(StopCleanupEffectDataV1<'held>),
    /// Carries only completed observation DATA, without any new child effect.
    Observed(StopCleanupObservedDataV1<'held>),
}

impl<'held> StopCleanupReplyDataV1<'held> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        self.decision_v1()?;
        Ok(())
    }

    /// Borrows the sole strict decision and compares its repeated opening.
    ///
    /// # Errors
    /// Refuses another branch, malformed nested DATA or a changed opening.
    pub fn decision_v1(self) -> Result<StopCleanupDecisionDataV1<'held>, HistoryErrorV1> {
        let (query, decision) = match self.decision_frame.get(..8) {
            Some(b"AOSHSE02") => {
                let value = StopCleanupEffectDataV1::decode_v1(self.decision_frame)?;
                (value.query_digest, StopCleanupDecisionDataV1::Effect(value))
            }
            Some(b"AOSHSO02") => {
                let value = StopCleanupObservedDataV1::decode_v1(self.decision_frame)?;
                (
                    value.query_digest,
                    StopCleanupDecisionDataV1::Observed(value),
                )
            }
            _ => return Err(HistoryErrorV1::Malformed),
        };
        if self.query_digest != query {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(decision)
    }
}

frame!(StopCleanupObservedDataV1, b"AOSHSO02", b"aos.sandbox.root.stop-cleanup.observed.v1\0", 6,
    /// Original opening commitment.
    query_digest: 32,
    /// Explicit branch selector:1 for completed V7,2 for cleanup lineage648.
    observation_kind: 1,
    /// Exact canonical completed row; supplies no reconstructed native owner.
    observation: crate::host_cleanup_lineage::HOST_CLEANUP_LINEAGE_BYTES_V1,
    /// Actual Root paired sample used for this observation.
    root_sample: ACQUISITION_RAW_PAIR_BYTES_V2,
    /// Exclusive current Root policy wall expiry.
    policy_expiry: 8,
    /// Narrowed deadline bounded by the unchanged original Source22 D.
    cutoff: 8,
);

frame!(StopCleanupSignatureDataV1, b"AOSHSG02", b"aos.sandbox.root.stop-cleanup.signature.v1\0", 3,
    /// Original opening commitment.
    query_digest: 32,
    /// Exact normalized subject commitment of the held effect reply.
    decision_digest: 32,
    /// Canonical ordinary Controller signature envelope, independently verified by Root.
    canonical_signature: u32::MAX as usize,
);

frame!(StopCleanupObservedDecisionDataV1, b"AOSHSD02", b"aos.sandbox.root.stop-cleanup.observed-decision.v1\0", 2,
    /// Original opening commitment.
    query_digest: 32,
    /// Exact effect or completed-observation decision; carries no signature.
    decision_digest: 32,
);

frame!(StopCleanupFinalDataV1, b"AOSHSF02", b"aos.sandbox.root.stop-cleanup.final.v1\0", 6,
    /// Original opening commitment.
    query_digest: 32,
    /// Actual final fresh Host3 request ID.
    host_query: 16,
    /// Actual final Host Session continuously retained by Source22.
    host_session: 32,
    /// Exact final signed Host3 request packet SHA256.
    host_request: 32,
    /// Exact final canonical signed Host3 outcome packet SHA256.
    host_outcome: 32,
    /// Exact final Host3 body SHA256.
    host_body: 32,
);

frame!(StopCleanupReceiptDataV1, b"AOSHSR02", b"aos.sandbox.root.stop-cleanup.receipt.v1\0", 4,
    /// Original opening commitment.
    query_digest: 32,
    /// Exact effect or completed-observation decision commitment.
    decision_digest: 32,
    /// Actual final canonical signed Host3 outcome packet SHA256.
    terminal_host_outcome: 32,
    /// Same narrowed mechanical cutoff; never a fresh relative interval.
    cutoff: 8,
);

fn exact_nonzero(bytes: &[u8], width: usize) -> Result<(), HistoryErrorV1> {
    if bytes.len() != width {
        return Err(HistoryErrorV1::Extent);
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(HistoryErrorV1::Malformed);
    }
    Ok(())
}

fn integer(bytes: &[u8]) -> Result<u64, HistoryErrorV1> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| HistoryErrorV1::Extent)?,
    ))
}

fn temporal(
    sample: &[u8],
    expiry: &[u8],
    cutoff: &[u8],
) -> Result<RawPairedClockSample, HistoryErrorV1> {
    let sample = decode_acquisition_raw_pair_data_v2(sample)?;
    let expiry = i64::from_be_bytes(expiry.try_into().map_err(|_| HistoryErrorV1::Extent)?);
    if sample.wall_seconds() >= expiry || sample.boottime_nanoseconds() >= integer(cutoff)? {
        return Err(HistoryErrorV1::Malformed);
    }
    Ok(sample)
}

impl StopCleanupSubjectDataV1<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        CreateFinalityObservationAdmissionDataV1::require_key_v1(self.admission_key)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        for bytes in [
            self.admission,
            self.source_parent,
            self.host_session,
            self.host_request,
            self.host_outcome,
            self.host_body,
        ] {
            exact_nonzero(bytes, 32)?;
        }
        exact_nonzero(self.cleanup, 16)?;
        exact_nonzero(self.host_query, 16)?;
        if self.cleanup == self.host_query {
            return Err(HistoryErrorV1::Malformed);
        }
        let recover = decode_acquisition_raw_pair_data_v2(self.recover_original)?;
        let first = temporal(
            self.controller_first,
            self.recover_wall_expiry,
            self.cleanup_cutoff,
        )?;
        if first.host_boot_id() != recover.host_boot_id()
            || first.boottime_nanoseconds() < recover.boottime_nanoseconds()
            || integer(self.cleanup_cutoff)? > integer(self.recover_cutoff)?
        {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    /// Compares the exact opening to this fresh subject without granting authority.
    ///
    /// # Errors
    /// Refuses changed cleanup ID, pair coordinates, deadline or subject commitment.
    pub fn require_query_v1(self, query: StopCleanupQueryDataV1) -> Result<(), HistoryErrorV1> {
        let first = decode_acquisition_raw_pair_data_v2(self.controller_first)?;
        if query.controller_nonce.as_slice() != self.cleanup
            || query.original_boot != first.host_boot_id()
            || query.original_boottime_ns != first.boottime_nanoseconds()
            || query.original_cutoff_ns != integer(self.cleanup_cutoff)?
            || query.subject_bytes
                != u64::try_from(self.encoded_bytes_v1()?).map_err(|_| HistoryErrorV1::Extent)?
            || query.subject_digest != self.digest_v1()?
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}

impl StopCleanupEffectDataV1<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        let subject = HostStopCleanupSubjectDataV1::decode_v1(self.subject)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        let sample = temporal(self.root_sample, self.policy_expiry, self.cutoff)?;
        if subject.current_boot_v1() != &sample.host_boot_id()
            || integer(self.cutoff)? > subject.original_cutoff_v1()
        {
            return Err(HistoryErrorV1::Malformed);
        }
        // Plan, statement and body stay borrowed here. The actual funded
        // preparation independently rebuilds and compares their canonical bytes.
        Ok(())
    }
}

impl StopCleanupObservedDataV1<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        self.decision_digest_v1()?;
        temporal(self.root_sample, self.policy_expiry, self.cutoff)?;
        Ok(())
    }

    /// Commits only a strict Complete V7 or exact canonical cleanup lineage.
    ///
    /// # Errors
    /// Refuses unknown tags, a non-Complete V7 or malformed nested DATA.
    pub fn decision_digest_v1(self) -> Result<[u8; 32], HistoryErrorV1> {
        let observation = match self.observation_kind {
            [1] => StopCleanupObservationDataV1::Historical(
                crate::host_recovered_namespace::HostRecoveredNamespaceDataV7::decode_v7(
                    self.observation,
                )
                .map_err(|_| HistoryErrorV1::Malformed)?,
            ),
            [2] => StopCleanupObservationDataV1::Cleanup(
                crate::host_cleanup_lineage::HostCleanupLineageDataV1::decode_v1(self.observation)
                    .map_err(|_| HistoryErrorV1::Malformed)?,
            ),
            _ => return Err(HistoryErrorV1::Malformed),
        };
        stop_cleanup_observation_decision_digest_v1(observation)
            .map_err(|_| HistoryErrorV1::Malformed)
    }
}

impl StopCleanupSignatureDataV1<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        exact_nonzero(self.decision_digest, 32)
    }
}

impl StopCleanupObservedDecisionDataV1<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        exact_nonzero(self.query_digest, 32)?;
        exact_nonzero(self.decision_digest, 32)
    }
}

impl StopCleanupFinalDataV1<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        for bytes in [
            self.query_digest,
            self.host_session,
            self.host_request,
            self.host_outcome,
            self.host_body,
        ] {
            exact_nonzero(bytes, 32)?;
        }
        exact_nonzero(self.host_query, 16)
    }
}

impl StopCleanupReceiptDataV1<'_> {
    fn require_fields(self) -> Result<(), HistoryErrorV1> {
        for bytes in [
            self.query_digest,
            self.decision_digest,
            self.terminal_host_outcome,
        ] {
            exact_nonzero(bytes, 32)?;
        }
        if integer(self.cutoff)? == 0 {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
