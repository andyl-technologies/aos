//! Shares exact continuation receipt and native-position comparison grammar.
//!
//! ```text
//! receipt = exact-owner-record | latest-head[40] | names[48] | NEXT[8] | end[8]
//! ```
//!
//! These fields retain no native descriptors, paid owner or live readback proof.

use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};

use super::super::super::protected_names::ProtectedJournalNamesV1;
use super::super::outcome::*;
use super::super::{
    HEAD_BYTES, HistoryErrorV1, KEY_BYTES, KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    reader,
};
use super::{
    SIGNED_BOUND_RECORD_BYTES_V1, SignedBoundBodyDataV1, USE_ADMITTED_RECORD_BYTES_V1,
    UseAdmittedBodyDataV1,
};

/// Selects one exact owner, revision, phase and body as passive comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationKindV1 {
    /// Root revision three, after the actual reserved successor was reread.
    UseAdmitted,
    /// Root revision four, after the actual signature and request were produced.
    SignedBound,
    /// Root revision five after independent actual outcome verification.
    OutcomeRecorded,
    /// Root revision six after all original held owners and U have settled.
    Closed,
    /// Controller revision nine, phase eight, after actual Session completion.
    ControllerOutcomeRecorded,
    /// Controller revision ten, phase nine, after original U commit and releases.
    HandoffRetained,
    /// Source revision two, phase two, from its original Held owner.
    SourceReleased,
    /// Cache revision two, phase two, from its original Held owner.
    CacheReleased,
}

impl ContinuationKindV1 {
    /// Returns the exact version-one record extent for this closed schema.
    #[must_use]
    pub const fn record_bytes(self) -> usize {
        match self {
            Self::UseAdmitted => USE_ADMITTED_RECORD_BYTES_V1,
            Self::SignedBound => SIGNED_BOUND_RECORD_BYTES_V1,
            Self::OutcomeRecorded => ROOT_OUTCOME_RECORD_BYTES_V1,
            Self::Closed => ROOT_CLOSED_RECORD_BYTES_V1,
            Self::ControllerOutcomeRecorded => CONTROLLER_OUTCOME_RECORD_BYTES_V1,
            Self::HandoffRetained => HANDOFF_RETAINED_RECORD_BYTES_V1,
            Self::SourceReleased | Self::CacheReleased => RELEASED_RECORD_BYTES_V1,
        }
    }

    /// Returns the exact version-one native receipt extent.
    #[must_use]
    pub const fn receipt_bytes(self) -> usize {
        self.record_bytes() + HEAD_BYTES + 64
    }

    /// Returns the exact record revision of this closed schema.
    #[must_use]
    pub const fn revision(self) -> u8 {
        match self {
            Self::UseAdmitted => 3,
            Self::SignedBound => 4,
            Self::OutcomeRecorded => 5,
            Self::Closed => 6,
            Self::ControllerOutcomeRecorded => 9,
            Self::HandoffRetained => 10,
            Self::SourceReleased | Self::CacheReleased => 2,
        }
    }

    /// Returns the original historical owner of this closed schema.
    #[must_use]
    pub const fn owner(self) -> OwnerV1 {
        match self {
            Self::ControllerOutcomeRecorded | Self::HandoffRetained => OwnerV1::Controller,
            Self::SourceReleased => OwnerV1::Source,
            Self::CacheReleased => OwnerV1::Cache,
            _ => OwnerV1::Root,
        }
    }

    fn phase(self) -> u8 {
        match self {
            Self::ControllerOutcomeRecorded => 8,
            Self::HandoffRetained => 9,
            _ => self.revision(),
        }
    }
}

/// Borrows one exact continuation record beside its original native return.
#[derive(Clone, Copy)]
pub struct ContinuationNativeReceiptDataV1<'bytes> {
    /// The original complete owner-specific record bytes.
    pub record: &'bytes [u8],
    /// The original latest head atomically appended with that record.
    pub latest_head: [u8; HEAD_BYTES],
    /// The original protected authority writer's physical-name coordinates.
    pub names: ProtectedJournalNamesV1,
    /// The actual returned/readback next sequence after the pair.
    pub after_next: u64,
    /// The actual returned/readback durable byte end after the pair.
    pub after_end: u64,
}

impl<'bytes> ContinuationNativeReceiptDataV1<'bytes> {
    /// Borrows a complete fixed receipt under the exact closed Root schema.
    ///
    /// # Errors
    /// Rejects malformed record/head/body/lane/phase or missing native coordinates.
    pub fn decode(
        bytes: &'bytes [u8],
        lane: [u8; 16],
        kind: ContinuationKindV1,
    ) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self {
            record: input.bytes(kind.record_bytes())?,
            latest_head: input.array()?,
            names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            after_next: input.u64()?,
            after_end: input.u64()?,
        };
        input.finish()?;
        value.record_data(lane, kind)?;
        Ok(value)
    }

    /// Checks the exact row/head/body without equating DATA with a live append.
    ///
    /// # Errors
    /// Rejects a substituted schema, row, head, body, lane or absent position.
    pub fn record_data(
        self,
        lane: [u8; 16],
        kind: ContinuationKindV1,
    ) -> Result<RecordEnvelopeV1<'bytes>, HistoryErrorV1> {
        if self.record.len() != kind.record_bytes() || self.after_next == 0 || self.after_end == 0 {
            return Err(HistoryErrorV1::Extent);
        }
        ProtectedJournalNamesV1::from_bytes(&self.names.to_bytes())
            .map_err(|_| HistoryErrorV1::Malformed)?;
        let key = KeyV1::new(lane, kind.owner(), u64::from(kind.revision()))?;
        let record =
            RecordEnvelopeV1::decode(self.record, key, PhaseV1::new(kind.owner(), kind.phase())?)?;
        let latest = KeyV1::new(lane, kind.owner(), 0)?;
        LatestHeadV1::decode(&self.latest_head, latest)?.check_record(latest, record)?;
        match kind {
            ContinuationKindV1::UseAdmitted => {
                UseAdmittedBodyDataV1::decode(record.body())?;
            }
            ContinuationKindV1::SignedBound => {
                SignedBoundBodyDataV1::decode(record.body())?;
            }
            ContinuationKindV1::OutcomeRecorded => {
                RootOutcomeBodyDataV1::decode(record.body())?;
            }
            ContinuationKindV1::Closed => {
                RootClosedBodyDataV1::decode(record.body())?;
            }
            ContinuationKindV1::ControllerOutcomeRecorded => {
                ControllerOutcomeBodyDataV1::decode(record.body())?;
            }
            ContinuationKindV1::HandoffRetained => {
                HandoffRetainedBodyDataV1::decode(record.body())?;
            }
            ContinuationKindV1::SourceReleased | ContinuationKindV1::CacheReleased => {
                ReleasedBodyDataV1::decode(record.body(), kind.owner())?;
            }
        }
        Ok(record)
    }

    /// Writes the same actual receipt into caller-owned exact bounded storage.
    ///
    /// # Errors
    /// Rejects invalid receipt DATA or a differing destination extent.
    pub fn encode_into(
        self,
        lane: [u8; 16],
        kind: ContinuationKindV1,
        output: &mut [u8],
    ) -> Result<(), HistoryErrorV1> {
        self.record_data(lane, kind)?;
        if output.len() != kind.receipt_bytes() {
            return Err(HistoryErrorV1::Extent);
        }
        let record_end = self.record.len();
        output[..record_end].copy_from_slice(self.record);
        output[record_end..record_end + HEAD_BYTES].copy_from_slice(&self.latest_head);
        let offset = record_end + HEAD_BYTES;
        output[offset..offset + 48].copy_from_slice(&self.names.to_bytes());
        output[offset + 48..offset + 56].copy_from_slice(&self.after_next.to_be_bytes());
        output[offset + 56..].copy_from_slice(&self.after_end.to_be_bytes());
        Ok(())
    }

    /// Compares the exact predecessor and four-frame successor to a held return.
    ///
    /// # Errors
    /// Rejects changed predecessor, physical names, sequence or exact byte end.
    /// The caller must supply its actual retained return, never decoded authority.
    pub fn require_successor(
        self,
        lane: [u8; 16],
        kind: ContinuationKindV1,
        predecessor: [u8; 32],
        correlation: [u8; 32],
        before_names: ProtectedJournalNamesV1,
        before_next: u64,
        before_end: u64,
    ) -> Result<(), HistoryErrorV1> {
        let record = self.record_data(lane, kind)?;
        let append = encoded_transaction_append_bytes(
            [
                RecordShape {
                    key_bytes: KEY_BYTES,
                    value_bytes: Some(kind.record_bytes()),
                },
                RecordShape {
                    key_bytes: KEY_BYTES,
                    value_bytes: Some(HEAD_BYTES),
                },
            ]
            .into_iter(),
        )
        .map_err(|_| HistoryErrorV1::Extent)?;
        if record.coordinates().predecessor != predecessor
            || record.coordinates().correlation != correlation
            || self.names != before_names
            || before_next == 0
            || before_next.checked_add(4) != Some(self.after_next)
            || before_end.checked_add(append) != Some(self.after_end)
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}
