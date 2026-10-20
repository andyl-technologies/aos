//! Borrows the defining active recorder cut without reading its growing banks.
//!
//! The closed active marker describes the actual state immediately after begin:
//! attempted and failed are true, output bytes and recording rows are empty,
//! and all capacities are actual. Every other output and recorder stays fully
//! borrowed through both count and write. No lookup address crosses the codec.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crate::retained_metadata::{
    MetadataObserver, aliases::MetadataAliasAllocationFacts, records::MetadataCapacityRecord,
};
use serde::ser::{SerializeSeq, SerializeStruct};

#[derive(Serialize)]
struct ActiveOutput17 {
    capacity: usize,
    maximum: usize,
    initial_length: usize,
    attempted: bool,
    has_reference: bool,
}

#[derive(Serialize)]
struct ActiveRecorder17 {
    maximum_rows: usize,
    capacity_rows: usize,
    retained_rows: usize,
    alias_allocation: MetadataAliasAllocationFacts,
    initialized_lookup_entries: usize,
}

/// Borrows all non-growing source fields of one actual output recorder cut.
///
/// This view is DATA only. Its private defining constructor grants no action,
/// renewed budget, Source proof or Capture publication permission.
pub(crate) struct NativeCaptureOutputCut17<'a> {
    role: NativeRestoredSettledCaptureOutput,
    before: &'a [Output],
    active: ActiveOutput17,
    after: &'a [Output],
    limits: &'a [usize; 5],
    cut: usize,
    active_recorder: ActiveRecorder17,
    other_records: &'a Option<MetadataRecordBank>,
    other_aliases: &'a Option<MetadataAliasBank>,
    reserved: bool,
    failed: bool,
}

impl NativeRestoredSettledCaptureOutputs {
    /// Spends one output while lending its exact active source cut separately.
    ///
    /// Active bytes/rows grow after this cut and are excluded by its explicit
    /// discriminator. Every completed or partial other bank remains in the loan.
    /// No borrowed graph reenters the current mutable output or recorder banks.
    ///
    /// # Errors
    /// Refuses another role, missing reservation, an already used or poisoned
    /// bank, initialized active rows/lookups, or an existing output reference.
    pub(crate) fn begin_recorded_write_cut_data(
        &mut self,
        role: NativeRestoredSettledCaptureOutput,
    ) -> Result<
        (
            &mut MetadataRecordBank,
            &mut MetadataAliasBank,
            NativeRecordedOutput17<'_>,
            NativeCaptureOutputCut17<'_>,
        ),
        ProviderError,
    > {
        self.ensure_usable()?;
        let cut = match role {
            NativeRestoredSettledCaptureOutput::Before => 0,
            NativeRestoredSettledCaptureOutput::After => 1,
            _ => return Err(refused()),
        };
        self.failed = true;
        let [before_records, after_records] = &mut self.records;
        let [before_aliases, after_aliases] = &mut self.aliases;
        let (records, aliases, other_records, other_aliases) = if cut == 0 {
            (before_records, before_aliases, after_records, after_aliases)
        } else {
            (after_records, after_aliases, before_records, before_aliases)
        };
        let records = records.as_mut().ok_or_else(refused)?;
        let aliases = aliases.as_mut().ok_or_else(refused)?;
        if !records.rows().is_empty()
            || aliases.retained_rows() != 0
            || aliases.current17_initialized_lookup_entries_data() != 0
        {
            return Err(refused());
        }
        let (before, selected) = self.banks.split_at_mut(role.index());
        let (output, after) = selected.split_first_mut().ok_or_else(refused)?;
        if std::mem::replace(&mut output.attempted, true)
            || !output.bytes.is_empty()
            || output.reference.is_some()
        {
            return Err(refused());
        }
        let active = ActiveOutput17 {
            capacity: output.bytes.capacity(),
            maximum: self.limits[role.index()],
            initial_length: output.bytes.len(),
            attempted: output.attempted,
            has_reference: output.reference.is_some(),
        };
        let active_recorder = ActiveRecorder17 {
            maximum_rows: records.maximum_rows(),
            capacity_rows: records.capacity_rows(),
            retained_rows: records.rows().len(),
            alias_allocation: aliases.allocation_facts(),
            initialized_lookup_entries: aliases.current17_initialized_lookup_entries_data(),
        };
        let cut_view = NativeCaptureOutputCut17 {
            role,
            before,
            active,
            after,
            limits: &self.limits,
            cut,
            active_recorder,
            other_records,
            other_aliases,
            reserved: self.reserved,
            failed: self.failed,
        };
        Ok((
            records,
            aliases,
            NativeRecordedOutput17 {
                output,
                maximum: self.limits[role.index()],
                failed: &mut self.failed,
            },
            cut_view,
        ))
    }

    /// Observes every actual completed/partial output and recorder bank.
    ///
    /// # Errors
    /// Refuses metadata capacity or checked native-layout overflow.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        for bank in &self.banks {
            observe_output(bank, observer)?;
        }
        for (records, aliases) in self.records.iter().zip(&self.aliases) {
            observe_recorder(records, aliases, observer)?;
        }
        Ok(())
    }
}

fn observe_output(
    output: &Output,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.observe(&output.bytes)?;
    observer.observe(&output.reference)
}

fn observe_recorder(
    records: &Option<MetadataRecordBank>,
    aliases: &Option<MetadataAliasBank>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    if let Some(records) = records {
        records.observe_current17_storage_data(observer)?;
    }
    if let Some(aliases) = aliases {
        aliases.observe_current17_storage_data(observer)?;
    }
    Ok(())
}

impl NativeCaptureOutputCut17<'_> {
    /// Observes actual retained capacities at the same active-recorder cut.
    ///
    /// # Errors
    /// Refuses metadata capacity or checked native-layout overflow.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        for output in self.before {
            observe_output(output, observer)?;
        }
        observer.vector::<u8>(self.active.capacity)?;
        for output in self.after {
            observe_output(output, observer)?;
        }
        if self.cut == 1 {
            observe_recorder(self.other_records, self.other_aliases, observer)?;
        }
        observer.vector::<MetadataCapacityRecord>(self.active_recorder.capacity_rows)?;
        MetadataAliasBank::observe_current17_capacities_data(
            self.active_recorder.alias_allocation.row_capacity,
            self.active_recorder.alias_allocation.lookup_capacity,
            observer,
        )?;
        if self.cut == 0 {
            observe_recorder(self.other_records, self.other_aliases, observer)?;
        }
        Ok(())
    }
}

struct OutputView17<'a>(&'a Output);
impl Serialize for OutputView17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Output {
            bytes,
            reference,
            attempted,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeCaptureRetainedOutput17", 3)?;
        fields.serialize_field(
            "bytes",
            &(BorrowedCompactBytes::new(bytes), bytes.capacity()),
        )?;
        fields.serialize_field("reference", reference)?;
        fields.serialize_field("attempted", attempted)?;
        fields.end()
    }
}

struct RecordView17<'a>(&'a MetadataRecordBank);
impl Serialize for RecordView17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.0.maximum_rows(), self.0.capacity_rows(), self.0).serialize(serializer)
    }
}

struct AliasView17<'a>(&'a MetadataAliasBank);
impl Serialize for AliasView17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            self.0.allocation_facts(),
            self.0.current17_initialized_lookup_entries_data(),
            self.0,
        )
            .serialize(serializer)
    }
}

#[derive(Serialize)]
struct RetainedRecorder17<'a> {
    records: Option<RecordView17<'a>>,
    aliases: Option<AliasView17<'a>>,
}

struct CutBanks17<'a>(&'a NativeCaptureOutputCut17<'a>);
impl Serialize for CutBanks17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(5))?;
        for bank in self.0.before {
            sequence.serialize_element(&("retained", OutputView17(bank)))?;
        }
        sequence.serialize_element(&("active_recorder17", &self.0.active))?;
        for bank in self.0.after {
            sequence.serialize_element(&("retained", OutputView17(bank)))?;
        }
        sequence.end()
    }
}

struct CutRecorders17<'a>(&'a NativeCaptureOutputCut17<'a>);
impl Serialize for CutRecorders17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(2))?;
        let other = RetainedRecorder17 {
            records: self.0.other_records.as_ref().map(RecordView17),
            aliases: self.0.other_aliases.as_ref().map(AliasView17),
        };
        if self.0.cut == 1 {
            sequence.serialize_element(&("retained", &other))?;
        }
        sequence.serialize_element(&("active_recorder17", &self.0.active_recorder))?;
        if self.0.cut == 0 {
            sequence.serialize_element(&("retained", &other))?;
        }
        sequence.end()
    }
}

impl Serialize for NativeCaptureOutputCut17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let role = match self.role {
            NativeRestoredSettledCaptureOutput::Before => "before",
            NativeRestoredSettledCaptureOutput::After => "after",
            _ => return Err(serde::ser::Error::custom("native active output role")),
        };
        let mut fields = serializer.serialize_struct("NativeCaptureActiveRecorderCut17", 7)?;
        fields.serialize_field(
            "schema",
            "source-private.native-capture-active-recorder-cut/17",
        )?;
        fields.serialize_field("active_role", role)?;
        fields.serialize_field("banks", &CutBanks17(self))?;
        fields.serialize_field("limits", self.limits)?;
        fields.serialize_field("recorders", &CutRecorders17(self))?;
        fields.serialize_field("reserved", &self.reserved)?;
        fields.serialize_field("failed", &self.failed)?;
        fields.end()
    }
}

struct FullBanks17<'a>(&'a [Output; 5]);
impl Serialize for FullBanks17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(5))?;
        for bank in self.0 {
            sequence.serialize_element(&OutputView17(bank))?;
        }
        sequence.end()
    }
}

struct FullRecorders17<'a>(&'a NativeRestoredSettledCaptureOutputs);
impl Serialize for FullRecorders17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(2))?;
        for (records, aliases) in self.0.records.iter().zip(&self.0.aliases) {
            sequence.serialize_element(&RetainedRecorder17 {
                records: records.as_ref().map(RecordView17),
                aliases: aliases.as_ref().map(AliasView17),
            })?;
        }
        sequence.end()
    }
}

impl Serialize for NativeRestoredSettledCaptureOutputs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("NativeCaptureRetainedOutputs17", 6)?;
        fields.serialize_field(
            "schema",
            "source-private.native-capture-retained-outputs/17",
        )?;
        fields.serialize_field("banks", &FullBanks17(&self.banks))?;
        fields.serialize_field("limits", &self.limits)?;
        fields.serialize_field("recorders", &FullRecorders17(self))?;
        fields.serialize_field("reserved", &self.reserved)?;
        fields.serialize_field("failed", &self.failed)?;
        fields.end()
    }
}

/// Names borrowed cut/iterator views without changing any lifetime action row.
pub(super) const fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<NativeCaptureOutputCut17<'static>>()
        + size_of::<ActiveOutput17>()
        + size_of::<ActiveRecorder17>()
        + size_of::<RetainedRecorder17<'static>>()
        + size_of::<OutputView17<'static>>()
        + size_of::<RecordView17<'static>>()
        + size_of::<AliasView17<'static>>()
        + size_of::<CutBanks17<'static>>()
        + size_of::<CutRecorders17<'static>>()
        + size_of::<FullBanks17<'static>>()
        + size_of::<FullRecorders17<'static>>()
        + size_of::<MetadataAliasAllocationFacts>()
        + size_of::<std::slice::Iter<'static, Output>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outputs() -> NativeRestoredSettledCaptureOutputs {
        NativeRestoredSettledCaptureOutputs {
            banks: std::array::from_fn(|_| Output {
                bytes: Vec::with_capacity(16384),
                reference: None,
                attempted: false,
            }),
            limits: [16384; 5],
            records: std::array::from_fn(|_| Some(MetadataRecordBank::reserve(64).unwrap())),
            aliases: std::array::from_fn(|_| Some(MetadataAliasBank::reserve(64).unwrap())),
            reserved: true,
            failed: false,
        }
    }

    #[test]
    fn active_cut_preserves_prior_outputs_and_records_while_own_banks_grow() {
        let mut outputs = outputs();
        outputs
            .write_data(
                NativeRestoredSettledCaptureOutput::Control,
                &serde_json::json!({"control": "actual prior bytes"}),
            )
            .unwrap();
        {
            let (records, aliases, writer, cut) = outputs
                .begin_recorded_write_cut_data(NativeRestoredSettledCaptureOutput::Before)
                .unwrap();
            let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
            cut.observe_current17_metadata_data(&mut observer).unwrap();
            let _ = observer.finish();
            writer.write_data(&cut).unwrap();
        }
        let before_bytes = outputs
            .completed_data(NativeRestoredSettledCaptureOutput::Before)
            .unwrap()
            .1
            .to_vec();
        let prior_rows = serde_json::to_value(outputs.records[0].as_ref().unwrap()).unwrap();
        let prior_control = outputs
            .completed_data(NativeRestoredSettledCaptureOutput::Control)
            .unwrap()
            .1
            .to_vec();
        {
            let (records, aliases, writer, cut) = outputs
                .begin_recorded_write_cut_data(NativeRestoredSettledCaptureOutput::After)
                .unwrap();
            let initial = serde_json::to_value(&cut).unwrap();
            assert_eq!(initial["failed"], true);
            assert_eq!(initial["reserved"], true);
            assert_eq!(initial["active_role"], "after");
            assert_eq!(initial["banks"][4][0], "active_recorder17");
            assert_eq!(initial["banks"][4][1]["initial_length"], 0);
            assert_eq!(initial["banks"][4][1]["attempted"], true);
            assert_eq!(initial["banks"][4][1]["has_reference"], false);
            assert_eq!(initial["recorders"][0][1]["records"][2], prior_rows);
            let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
            cut.observe_current17_metadata_data(&mut observer).unwrap();
            let _ = observer.finish();
            assert_eq!(serde_json::to_value(&cut).unwrap(), initial);
            writer.write_data(&cut).unwrap();
        }
        assert!(!outputs.failed);
        assert_eq!(
            outputs
                .completed_data(NativeRestoredSettledCaptureOutput::Before)
                .unwrap()
                .1,
            before_bytes
        );
        assert_eq!(
            outputs
                .completed_data(NativeRestoredSettledCaptureOutput::Control)
                .unwrap()
                .1,
            prior_control
        );
        let encoded = outputs
            .completed_data(NativeRestoredSettledCaptureOutput::After)
            .unwrap()
            .1;
        let snapshot: serde_json::Value = serde_json::from_slice(encoded).unwrap();
        assert_eq!(snapshot["failed"], true);
        assert_eq!(snapshot["recorders"][1][0], "active_recorder17");
        assert_eq!(snapshot["recorders"][1][1]["retained_rows"], 0);
    }

    #[test]
    fn abandoned_cut_keeps_poison_and_all_partial_bytes() {
        let mut outputs = outputs();
        {
            let (records, aliases, writer, cut) = outputs
                .begin_recorded_write_cut_data(NativeRestoredSettledCaptureOutput::Before)
                .unwrap();
            let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
            cut.observe_current17_metadata_data(&mut observer).unwrap();
            let _ = observer.finish();
            drop(writer);
        }
        assert!(outputs.failed);
        assert!(!outputs.records[0].as_ref().unwrap().rows().is_empty());
        assert!(
            outputs
                .begin_recorded_write_cut_data(NativeRestoredSettledCaptureOutput::Before)
                .is_err()
        );
        assert!(outputs.banks[2].attempted);
        assert!(outputs.banks[2].bytes.is_empty());
    }
}
