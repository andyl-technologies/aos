//! Retains five separately prepaid native Capture17 output banks on failure.
//!
//! Counting and writing use the same borrowed serializer and compare the whole
//! emitted-byte digest, not just its length. These are inert output operations;
//! the private live consumer separately authenticates current owners, the real
//! Source proof and its spent action before invoking the writer.

use super::PacketRestoredSettledNativeStorageData;
use crate::ProviderError;
use crate::retained_metadata::{aliases::MetadataAliasBank, records::MetadataRecordBank};
use crucible_node_contract::{ContentRef, canonical};
use serde::Serialize;
use std::{io::Write, mem::size_of};

/// Selects a closed output slot without conferring a publication capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeRestoredSettledCaptureOutput {
    Snapshot,
    Control,
    Before,
    Anchor,
    After,
}

impl NativeRestoredSettledCaptureOutput {
    const fn index(self) -> usize {
        match self {
            Self::Snapshot => 0,
            Self::Control => 1,
            Self::Before => 2,
            Self::Anchor => 3,
            Self::After => 4,
        }
    }
}

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    reference: Option<ContentRef>,
    attempted: bool,
}

/// Owns all actual outputs and recording banks beside the once Capture attempt.
pub(crate) struct NativeRestoredSettledCaptureOutputs {
    banks: [Output; 5],
    limits: [usize; 5],
    records: [Option<MetadataRecordBank>; 2],
    aliases: [Option<MetadataAliasBank>; 2],
    reserved: bool,
    failed: bool,
}

impl NativeRestoredSettledCaptureOutputs {
    /// Installs the owner before any buffer or metadata reservation can fail.
    ///
    /// This requires an already produced defining row, but does not spend or
    /// authenticate a native grant. The actual live caller must debit first.
    pub(crate) fn reserve_into(
        row: &PacketRestoredSettledNativeStorageData,
        destination: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            return Err(refused());
        }
        let outputs = row.output_limits_data();
        let limits = [
            outputs.native_snapshot_bytes,
            outputs.current_control_bytes,
            outputs.native_before_bytes,
            outputs.anchor_bytes,
            outputs.native_after_bytes,
        ];
        let mut checked = [0usize; 5];
        for (out, limit) in checked.iter_mut().zip(limits) {
            *out = usize::try_from(limit.get()).map_err(|_| refused())?;
        }
        *destination = Some(Self {
            banks: std::array::from_fn(|_| Output::default()),
            limits: checked,
            records: std::array::from_fn(|_| None),
            aliases: std::array::from_fn(|_| None),
            reserved: false,
            failed: true,
        });
        let owner = destination.as_mut().ok_or_else(refused)?;
        for (bank, maximum) in owner.banks.iter_mut().zip(owner.limits) {
            bank.bytes
                .try_reserve_exact(maximum)
                .map_err(|_| exhausted())?;
            if bank.bytes.capacity() < maximum {
                return Err(exhausted());
            }
        }
        for (index, rows) in row.metadata_row_limits_data().into_iter().enumerate() {
            owner.records[index] = Some(MetadataRecordBank::reserve(rows)?);
            owner.aliases[index] = Some(MetadataAliasBank::reserve(rows)?);
        }
        owner.reserved = true;
        owner.failed = false;
        Ok(())
    }

    /// Spends one output slot and lends disjoint banks for its actual graph.
    ///
    /// The caller records the full source graph into the returned banks, then
    /// passes that same borrowed graph to the returned writer. The writer owns
    /// only the selected output bank, so immutable graph loans of the metadata
    /// banks remain valid throughout counting and encoding. Dropping this loan
    /// or failing either phase leaves the output owner poisoned and preserves
    /// every completed row and partial byte.
    ///
    /// # Errors
    /// Refuses a used output or cut, absent reservation, or a poisoned owner.
    pub(crate) fn begin_recorded_write_data(
        &mut self,
        role: NativeRestoredSettledCaptureOutput,
    ) -> Result<
        (
            &mut MetadataRecordBank,
            &mut MetadataAliasBank,
            NativeRecordedOutput17<'_>,
        ),
        ProviderError,
    > {
        let (records, aliases, writer, _cut) = self.begin_recorded_write_cut_data(role)?;
        Ok((records, aliases, writer))
    }

    /// Counts and writes one exact borrowed object without growing its bank.
    ///
    /// Any serializer, extent, stable-byte or fullref failure leaves this owner
    /// poisoned and preserves all partial bytes. No slot is cleared or retried.
    pub(crate) fn write_data(
        &mut self,
        role: NativeRestoredSettledCaptureOutput,
        state: &impl Serialize,
    ) -> Result<(), ProviderError> {
        self.ensure_usable()?;
        self.failed = true;
        let index = role.index();
        let output = &mut self.banks[index];
        if std::mem::replace(&mut output.attempted, true) || !output.bytes.is_empty() {
            return Err(refused());
        }
        let mut count = Count {
            used: 0,
            maximum: self.limits[index],
            hash: blake3::Hasher::new(),
        };
        serde_json::to_writer(&mut count, state).map_err(|_| exhausted())?;
        let expected = count.hash.finalize();
        let mut bounded = Bounded {
            output: &mut output.bytes,
            maximum: count.used,
        };
        serde_json::to_writer(&mut bounded, state).map_err(|_| exhausted())?;
        if output.bytes.len() != count.used || blake3::hash(&output.bytes) != expected {
            return Err(refused());
        }
        output.reference = Some(canonical::content_ref(&output.bytes, "application/json")?);
        self.failed = false;
        Ok(())
    }

    /// Lends only a completed same-slot output, never a publication permission.
    pub(crate) fn completed_data(
        &self,
        role: NativeRestoredSettledCaptureOutput,
    ) -> Result<(&ContentRef, &[u8]), ProviderError> {
        self.ensure_usable()?;
        let output = &self.banks[role.index()];
        Ok((
            output.reference.as_ref().ok_or_else(refused)?,
            &output.bytes,
        ))
    }

    fn ensure_usable(&self) -> Result<(), ProviderError> {
        if self.failed || !self.reserved {
            return Err(refused());
        }
        Ok(())
    }
}

/// Owns one spent output bank while its disjoint recording banks stay loaned.
pub(crate) struct NativeRecordedOutput17<'a> {
    output: &'a mut Output,
    maximum: usize,
    failed: &'a mut bool,
}

impl NativeRecordedOutput17<'_> {
    /// Writes the exact recorded graph and closes only this successful output.
    ///
    /// # Errors
    /// Refuses a serializer failure, growth, changed count/hash, or invalid ref.
    pub(crate) fn write_data(self, state: &impl Serialize) -> Result<(), ProviderError> {
        let mut count = Count {
            used: 0,
            maximum: self.maximum,
            hash: blake3::Hasher::new(),
        };
        serde_json::to_writer(&mut count, state).map_err(|_| exhausted())?;
        let expected = count.hash.finalize();
        let mut bounded = Bounded {
            output: &mut self.output.bytes,
            maximum: count.used,
        };
        serde_json::to_writer(&mut bounded, state).map_err(|_| exhausted())?;
        if self.output.bytes.len() != count.used || blake3::hash(&self.output.bytes) != expected {
            return Err(refused());
        }
        self.output.reference = Some(canonical::content_ref(
            &self.output.bytes,
            "application/json",
        )?);
        *self.failed = false;
        Ok(())
    }
}

struct Count {
    used: usize,
    maximum: usize,
    hash: blake3::Hasher,
}

impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|used| *used <= self.maximum)
            .ok_or_else(|| std::io::Error::other("native17 output count limit"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Bounded<'a> {
    output: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for Bounded<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .output
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum && *end <= self.output.capacity())
            .ok_or_else(|| std::io::Error::other("native17 output write limit"))?;
        self.output.extend_from_slice(bytes);
        debug_assert_eq!(self.output.len(), end);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) const fn counter_scratch_data() -> usize {
    active_cut17::counter_scratch_data()
        + snapshot17::native_capture17_snapshot_counter_scratch_data()
        + size_of::<NativeRestoredSettledCaptureOutputs>()
        + size_of::<Output>()
        + size_of::<NativeRecordedOutput17<'static>>()
        + size_of::<
            Result<
                (
                    &'static mut MetadataRecordBank,
                    &'static mut MetadataAliasBank,
                    NativeRecordedOutput17<'static>,
                ),
                ProviderError,
            >,
        >()
        + size_of::<NativeRestoredSettledCaptureOutput>()
        + size_of::<[usize; 2]>()
        + size_of::<Count>()
        + size_of::<Bounded<'static>>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Option<ContentRef>>()
        + size_of::<Result<ContentRef, crucible_node_contract::ContractError>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<[usize; 5]>()
        + size_of::<[crucible_node_contract::U64; 5]>()
        + size_of::<std::array::IntoIter<crucible_node_contract::U64, 5>>()
        + size_of::<
            std::iter::Zip<
                std::slice::IterMut<'static, usize>,
                std::array::IntoIter<crucible_node_contract::U64, 5>,
            >,
        >()
        + size_of::<
            std::iter::Zip<std::slice::IterMut<'static, Output>, std::array::IntoIter<usize, 5>>,
        >()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<usize, 2>>>()
        + size_of::<Option<(&mut Output, usize)>>()
        + size_of::<Option<(usize, usize)>>()
        + size_of::<Result<(&ContentRef, &[u8]), ProviderError>>()
        + size_of::<blake3::Hash>()
        + size_of::<blake3::Hasher>()
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native17 independent output or recording bank")
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native17 output attempt unavailable or previously spent")
}

#[cfg(test)]
mod recorded_output_tests {
    use super::*;
    use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
    use std::cell::Cell;
    use std::rc::Rc;

    // These are inert output banks. The fixture supplies no native action or
    // Source capability, and exercises only the field-split encoding boundary.
    fn output_banks() -> Result<NativeRestoredSettledCaptureOutputs, ProviderError> {
        let mut banks = std::array::from_fn(|_| Output::default());
        for bank in &mut banks {
            bank.bytes
                .try_reserve_exact(4096)
                .map_err(|_| exhausted())?;
        }
        Ok(NativeRestoredSettledCaptureOutputs {
            banks,
            limits: [4096; 5],
            records: [
                Some(MetadataRecordBank::reserve(8)?),
                Some(MetadataRecordBank::reserve(8)?),
            ],
            aliases: [
                Some(MetadataAliasBank::reserve(8)?),
                Some(MetadataAliasBank::reserve(8)?),
            ],
            reserved: true,
            failed: false,
        })
    }

    #[test]
    fn recorded_graph_keeps_its_actual_bank_loans_until_encoding_finishes()
    -> Result<(), ProviderError> {
        let actual = Rc::new(vec![1u8, 2, 3]);
        let mut outputs = output_banks()?;
        let (records, aliases, writer) =
            outputs.begin_recorded_write_data(NativeRestoredSettledCaptureOutput::Before)?;
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        observer.shared_original(MetadataSharedKind::ContentBytes, actual.as_ref())?;
        observer.observe(actual.as_ref())?;
        observer.finish();

        writer.write_data(&(&*records, &*aliases))?;
        let (_, bytes) = outputs.completed_data(NativeRestoredSettledCaptureOutput::Before)?;
        assert!(!bytes.is_empty());
        assert_eq!(
            outputs.records[0]
                .as_ref()
                .ok_or_else(refused)?
                .rows()
                .len(),
            2
        );
        assert_eq!(
            outputs.aliases[0]
                .as_ref()
                .ok_or_else(refused)?
                .retained_rows(),
            1
        );
        assert!(
            outputs
                .begin_recorded_write_data(NativeRestoredSettledCaptureOutput::Before)
                .is_err()
        );
        Ok(())
    }

    struct ChangingGraph(Cell<u64>);

    impl Serialize for ChangingGraph {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let value = self.0.get();
            self.0.set(value + 1);
            serializer.serialize_u64(value)
        }
    }

    #[test]
    fn changed_graph_and_abandoned_loan_keep_the_same_output_poisoned() -> Result<(), ProviderError>
    {
        let mut outputs = output_banks()?;
        let (_, _, writer) =
            outputs.begin_recorded_write_data(NativeRestoredSettledCaptureOutput::After)?;
        assert!(writer.write_data(&ChangingGraph(Cell::new(1))).is_err());
        assert_eq!(outputs.banks[4].bytes, b"2");
        assert!(outputs.banks[4].attempted);
        assert!(outputs.banks[4].reference.is_none());
        assert!(
            outputs
                .completed_data(NativeRestoredSettledCaptureOutput::After)
                .is_err()
        );
        assert!(
            outputs
                .begin_recorded_write_data(NativeRestoredSettledCaptureOutput::After)
                .is_err()
        );

        let mut abandoned = output_banks()?;
        {
            let _loan =
                abandoned.begin_recorded_write_data(NativeRestoredSettledCaptureOutput::Before)?;
        }
        assert!(abandoned.failed);
        assert!(abandoned.banks[2].attempted);
        assert!(
            abandoned
                .begin_recorded_write_data(NativeRestoredSettledCaptureOutput::Before)
                .is_err()
        );
        Ok(())
    }
}

#[path = "restored_settled_capture_output/active_cut17.rs"]
mod active_cut17;
pub(crate) use active_cut17::NativeCaptureOutputCut17;

mod snapshot17;
pub(crate) use snapshot17::{
    NativeCapture17SnapshotStorageData, native_capture17_snapshot_counter_scratch_data,
};
