//! Keeps every Source observation partial beneath its original once attempt.

use super::*;

#[path = "owner/checkpoint_cache17.rs"]
mod checkpoint_cache17;
use std::io;

const BANKS: usize = 4;

pub(in super::super) struct OriginalSourceRestorationObservationAttempt {
    process: u32,
    thread: std::thread::ThreadId,
    source: *const PacketCompleteSemanticSource,
    controller: *const CnpController,
    binding: [u8; 32],
    reserved: bool,
    verified: bool,
    banks: [Vec<u8>; BANKS],
    values: [Option<serde_json::Value>; BANKS],
    record: Option<PacketNativeRestoredRecord>,
    underlying: Option<PacketNative5UnderlyingRecord>,
    scheduling: std::cell::OnceCell<NativeSchedulingObservation>,
}

impl OriginalSourceRestorationObservationAttempt {
    pub(super) fn minimum_bank_bytes(frame: usize) -> Result<usize, RuntimeError> {
        sum(
            [
                MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
                MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
                frame,
                frame,
            ],
            usize::MAX,
        )
    }

    pub(super) fn reserve_into(
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        binding: [u8; 32],
        frame: usize,
        slot: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if slot.is_some() || frame == 0 {
            return Err(RuntimeError::DuplicateOperation);
        }
        Self::minimum_bank_bytes(frame)?;
        // Install before the first fallible allocation. A partial reservation
        // cannot disappear or acquire a replacement identity after an error.
        *slot = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source,
            controller,
            binding,
            reserved: false,
            verified: false,
            banks: std::array::from_fn(|_| Vec::new()),
            values: std::array::from_fn(|_| None),
            record: None,
            underlying: None,
            scheduling: std::cell::OnceCell::new(),
        });
        let attempt = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        for (bank, maximum) in attempt.banks.iter_mut().zip([
            MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
            MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
            frame,
            frame,
        ]) {
            bank.try_reserve_exact(maximum)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        attempt.reserved = true;
        Ok(())
    }

    pub(super) fn authenticate_original(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        binding: [u8; 32],
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || self.binding != binding
            || !self.reserved
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn retain_value(
        &mut self,
        index: usize,
        value: serde_json::Value,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        if self.verified
            || index >= BANKS
            || self.values[index].is_some()
            || !self.banks[index].is_empty()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.values[index] = Some(value);
        let value = self.values[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        canonical::canonical_json_to_writer(
            value,
            &mut BankWriter {
                bytes: &mut self.banks[index],
                maximum,
            },
        )
        .map_err(|_| RuntimeError::InvalidReceipt)
    }

    pub(super) fn value(&self, index: usize) -> Result<&serde_json::Value, RuntimeError> {
        self.values
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn retain_record(
        &mut self,
        record: PacketNativeRestoredRecord,
    ) -> Result<(), RuntimeError> {
        if self.verified || self.record.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.record = Some(record);
        Ok(())
    }

    pub(super) fn record(&self) -> Result<&PacketNativeRestoredRecord, RuntimeError> {
        self.record.as_ref().ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn retain_underlying(
        &mut self,
        record: PacketNative5UnderlyingRecord,
    ) -> Result<(), RuntimeError> {
        if self.verified || self.underlying.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.underlying = Some(record);
        Ok(())
    }

    pub(super) fn underlying(&self) -> Result<&PacketNative5UnderlyingRecord, RuntimeError> {
        self.underlying
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn retain_scheduling(
        &self,
        value: NativeSchedulingObservation,
    ) -> Result<(), RuntimeError> {
        if self.verified || self.scheduling.get().is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.scheduling
            .set(value)
            .map_err(|_| RuntimeError::OutstandingObligations)
    }

    pub(super) fn scheduling(&self) -> Result<&NativeSchedulingObservation, RuntimeError> {
        self.scheduling.get().ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn finish_verified(&mut self) -> Result<(), RuntimeError> {
        if self.verified
            || !self.reserved
            || self.values.iter().any(Option::is_none)
            || self.banks.iter().any(Vec::is_empty)
            || self.record.is_none()
            || self.underlying.is_none()
            || self.scheduling.get().is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.verified = true;
        Ok(())
    }

    pub(super) fn authenticate_verified(&self) -> Result<(), RuntimeError> {
        if !self.verified || !self.reserved {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn allocated_bank_bytes_with_error<
        E: StorageError,
    >(
        &self,
    ) -> Result<usize, E> {
        self.banks.iter().try_fold(0usize, |bytes, bank| {
            bytes
                .checked_add(bank.capacity())
                .ok_or_else(|| E::limit("observation bank capacity overflow"))
        })
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retained_heap_bytes_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
            sum_with_error, value_storage_with_error,
        };
        let mut bytes = 0;
        for value in self.values.iter().flatten() {
            bytes = sum_with_error::<E, _>(
                [bytes, value_storage_with_error::<E>(value, 0, maximum)?],
                maximum,
            )?;
        }
        if let Some(record) = &self.record {
            let facts = restoration_activation_retained_native_evidence_data(
                record,
                self.underlying.as_ref(),
            )
            .map_err(E::unknown)?;
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                        &facts, maximum,
                    )?,
                ],
                maximum,
            )?;
        } else if self.underlying.is_some() {
            return Err(E::unknown("observation model lacks receipt"));
        }
        if let Some(observation) = self.scheduling.get() {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    NodeRuntime::capture_scheduling_observation_storage_data(observation, maximum)
                        .map_err(|_| E::limit("observation scheduling census"))?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

struct BankWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl io::Write for BankWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if total > self.maximum || total > self.bytes.capacity() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<OriginalSourceRestorationObservationAttempt>()
        + size_of::<Option<OriginalSourceRestorationObservationAttempt>>()
        + size_of::<&OriginalSourceRestorationObservationAttempt>()
        + size_of::<&mut OriginalSourceRestorationObservationAttempt>()
        + size_of::<Option<&OriginalSourceRestorationObservationAttempt>>()
        + size_of::<Option<&mut OriginalSourceRestorationObservationAttempt>>()
        + size_of::<Result<&OriginalSourceRestorationObservationAttempt, RuntimeError>>()
        + size_of::<Result<&mut OriginalSourceRestorationObservationAttempt, RuntimeError>>()
        + size_of::<Option<&NativeSchedulingObservation>>()
        + size_of::<std::cell::OnceCell<NativeSchedulingObservation>>()
        + size_of::<Result<(), NativeSchedulingObservation>>()
        + size_of::<BankWriter<'static>>()
        + size_of::<[usize; 4]>()
        + size_of::<std::array::IntoIter<usize, 4>>()
        + size_of::<
            std::iter::Zip<std::slice::IterMut<'static, Vec<u8>>, std::array::IntoIter<usize, 4>>,
        >()
        + size_of::<std::slice::Iter<'static, Vec<u8>>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<serde_json::Value>>>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<usize, io::Error>>()
        + size_of::<Result<&serde_json::Value, RuntimeError>>()
        + size_of::<Result<&PacketNativeRestoredRecord, RuntimeError>>()
        + size_of::<Result<&PacketNative5UnderlyingRecord, RuntimeError>>()
        + size_of::<Result<&NativeSchedulingObservation, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn observation_writer_keeps_partial_bytes_and_refuses_capacity_growth() {
        let mut bank = Vec::with_capacity(8);
        let capacity = bank.capacity();
        let mut writer = BankWriter {
            bytes: &mut bank,
            maximum: 5,
        };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"def").is_err());
        assert_eq!(writer.bytes.as_slice(), b"abc");
        assert_eq!(writer.bytes.capacity(), capacity);
        writer.write_all(b"de").unwrap();
        assert!(writer.write_all(b"f").is_err());
        assert_eq!(writer.bytes.as_slice(), b"abcde");
    }
}

#[cfg(test)]
mod partial_tests {
    use super::*;

    #[test]
    fn a_failed_actual_value_write_keeps_its_slot_and_cannot_complete() {
        // Raw private DATA only: null identity pointers cannot authenticate a
        // Source or Controller and no effect/capability constructor is called.
        let mut attempt = OriginalSourceRestorationObservationAttempt {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: std::ptr::null(),
            controller: std::ptr::null(),
            binding: [0; 32],
            reserved: true,
            verified: false,
            banks: std::array::from_fn(|_| Vec::with_capacity(1)),
            values: std::array::from_fn(|_| None),
            record: None,
            underlying: None,
            scheduling: std::cell::OnceCell::new(),
        };
        let value = serde_json::json!({"retained":"original"});
        assert!(attempt.retain_value(0, value.clone(), 1).is_err());
        assert_eq!(attempt.value(0).unwrap(), &value);
        let partial = attempt.banks[0].clone();
        assert!(attempt.retain_value(0, serde_json::Value::Null, 1).is_err());
        assert_eq!(attempt.value(0).unwrap(), &value);
        assert_eq!(attempt.banks[0], partial);
        assert!(attempt.finish_verified().is_err());
        assert!(attempt.authenticate_verified().is_err());
    }
}

impl OriginalSourceRestorationObservationAttempt {
    /// Lends the already verified immutable initial model as checkpoint DATA.
    ///
    /// The owning Source still authenticates its distinct seed and current
    /// native read. This helper neither repeats a native Observe nor replaces
    /// the first receipt after a progressed Producer attempt.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_producer_checkpoint_data(
        &self,
    ) -> Result<
        (
            &PacketNativeRestoredRecord,
            &crucible_node_provider::reference_packet::control::PacketNativeRecord,
            &ContentRef,
        ),
        RuntimeError,
    > {
        self.authenticate_verified()?;
        let PacketNative5UnderlyingRecord::Producer(producer) = self.underlying()? else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        Ok((self.record()?, producer, &self.scheduling()?.proof_ref))
    }
}

#[path = "owner/logical17.rs"]
mod logical17;

/// Lends the complete original Source-owned once-observation partial graph.
///
/// Historical model evidence stays distinct from the latest current checkpoint.
/// No private process identity, pointer or live OnceCell constructor is encoded.
pub(crate) struct OriginalSourceFirstObservationHistoryData<'a> {
    original: &'a OriginalSourceRestorationObservationAttempt,
    records: &'a std::cell::RefCell<
        crucible_node_provider::retained_metadata::records::MetadataRecordBank,
    >,
    aliases: &'a std::cell::RefCell<
        crucible_node_provider::retained_metadata::aliases::MetadataAliasBank,
    >,
}

impl OriginalSourceRestorationObservationAttempt {
    /// Lends an already verified first checkpoint as DATA for either native model.
    ///
    /// # Errors
    /// Refuses an incomplete actual first observation or missing retained owner.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_capture_checkpoint_data(
        &self,
    ) -> Result<
        (
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &ContentRef,
        ),
        RuntimeError,
    > {
        self.authenticate_verified()?;
        Ok((
            self.record()?,
            self.underlying()?,
            &self.scheduling()?.proof_ref,
        ))
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_data<'a>(
        &'a self,
        records: &'a std::cell::RefCell<
            crucible_node_provider::retained_metadata::records::MetadataRecordBank,
        >,
        aliases: &'a std::cell::RefCell<
            crucible_node_provider::retained_metadata::aliases::MetadataAliasBank,
        >,
    ) -> OriginalSourceFirstObservationHistoryData<'a> {
        OriginalSourceFirstObservationHistoryData {
            original: self,
            records,
            aliases,
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_metadata_demand_data(
        &self,
    ) -> Result<
        (
            crucible_node_provider::retained_metadata::RetainedProtocolMetadataFacts,
            usize,
        ),
        RuntimeError,
    > {
        if self.underlying.is_some() && self.record.is_none() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let Some(record) = self.record.as_ref() else {
            return Ok((Default::default(), 0));
        };
        let facts =
            restoration_activation_retained_native_evidence_data(record, self.underlying.as_ref())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        let transient = crucible_node_provider::reference_packet::service::complete_restore::activation::restoration_activation_historical_native_evidence_transient_bytes_data(
            record, self.underlying.as_ref(),
        ).map_err(|_| RuntimeError::ResourceLimit)?;
        Ok((facts, transient))
    }
}

struct HistoricalCommon<'a, T: ?Sized>(&'a T);

impl<
    T: serde::Serialize
        + crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk
        + ?Sized,
> serde::Serialize for HistoricalCommon<'_, T>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};
        let capacities =
            crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows(self.0);
        capacities
            .metadata_demand_data()
            .map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("FirstSourceObservationOwner", 2)?;
        value.serialize_field("value", self.0)?;
        value.serialize_field("capacities", &capacities)?;
        value.end()
    }
}

struct HistoricalValues<'a>(&'a [Option<serde_json::Value>; BANKS]);
struct HistoricalBanks<'a>(&'a [Vec<u8>; BANKS]);

impl serde::Serialize for HistoricalValues<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut values = serializer.serialize_seq(Some(BANKS))?;
        for value in self.0 {
            values.serialize_element(&HistoricalCommon(value))?;
        }
        values.end()
    }
}

impl serde::Serialize for HistoricalBanks<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut values = serializer.serialize_seq(Some(BANKS))?;
        for value in self.0 {
            values.serialize_element(&HistoricalCommon(value))?;
        }
        values.end()
    }
}

struct HistoricalUnderlying<'a>(&'a PacketNative5UnderlyingRecord);

impl serde::Serialize for HistoricalUnderlying<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("FirstSourceObservationUnderlying", 2)?;
        match self.0 {
            PacketNative5UnderlyingRecord::Producer(record) => {
                value.serialize_field("kind", "producer")?;
                value.serialize_field("value", record)?;
            }
            PacketNative5UnderlyingRecord::Reactive(record) => {
                value.serialize_field("kind", "reactive")?;
                value.serialize_field("value", record)?;
            }
        }
        value.end()
    }
}

struct HistoricalNativeCapacities<'a>(&'a OriginalSourceFirstObservationHistoryData<'a>);

impl serde::Serialize for HistoricalNativeCapacities<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};
        let owner = self.0;
        let Some(record) = &owner.original.record else {
            return serializer.serialize_none();
        };
        {
            let mut records = owner.records.try_borrow_mut().map_err(S::Error::custom)?;
            let mut aliases = owner.aliases.try_borrow_mut().map_err(S::Error::custom)?;
            let before = restoration_activation_retained_native_evidence_data(
                record,
                owner.original.underlying.as_ref(),
            )
            .map_err(S::Error::custom)?;
            let after = crucible_node_provider::reference_packet::service::complete_restore::activation::restoration_activation_record_native_evidence_metadata_data(
                record, owner.original.underlying.as_ref(), &mut records, &mut aliases,
            ).map_err(S::Error::custom)?;
            if before != after {
                return Err(S::Error::custom("first Source native owner changed"));
            }
        }
        let records = owner.records.try_borrow().map_err(S::Error::custom)?;
        let aliases = owner.aliases.try_borrow().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("FirstSourceObservationNativeCapacities", 5)?;
        value.serialize_field("record_capacity", &records.capacity_rows())?;
        value.serialize_field("record_maximum", &records.maximum_rows())?;
        value.serialize_field("records", &*records)?;
        value.serialize_field("alias_capacities", &aliases.capacity_rows())?;
        value.serialize_field("aliases", &*aliases)?;
        value.end()
    }
}

impl serde::Serialize for OriginalSourceFirstObservationHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};
        let OriginalSourceRestorationObservationAttempt {
            process: _,
            thread: _,
            source: _,
            controller: _,
            binding,
            reserved,
            verified,
            banks,
            values,
            record,
            underlying,
            scheduling,
        } = self.original;
        self.original
            .historical_metadata_demand_data()
            .map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("FirstSourceObservationHistory", 10)?;
        value.serialize_field(
            "schema",
            "source-private.source-first-observation-history/1",
        )?;
        value.serialize_field("binding", binding)?;
        value.serialize_field("reserved", reserved)?;
        value.serialize_field("verified", verified)?;
        value.serialize_field("banks", &HistoricalBanks(banks))?;
        value.serialize_field("values", &HistoricalValues(values))?;
        value.serialize_field("native_capacities", &HistoricalNativeCapacities(self))?;
        value.serialize_field("record", record)?;
        value.serialize_field("underlying", &underlying.as_ref().map(HistoricalUnderlying))?;
        value.serialize_field("scheduling", &scheduling.get().map(HistoricalCommon))?;
        value.end()
    }
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
-> usize {
    use crucible_node_provider::{
        ProviderError,
        retained_metadata::{
            RetainedProtocolMetadataFacts, aliases::MetadataAliasBank, records::MetadataRecordBank,
        },
    };
    use std::cell::{BorrowError, BorrowMutError, Ref, RefMut};
    crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data()
        + size_of::<OriginalSourceFirstObservationHistoryData<'static>>()
        + size_of::<HistoricalBanks<'static>>() + size_of::<HistoricalValues<'static>>()
        + size_of::<HistoricalUnderlying<'static>>() + size_of::<Option<HistoricalUnderlying<'static>>>()
        + size_of::<HistoricalNativeCapacities<'static>>()
        + size_of::<HistoricalCommon<'static, NativeSchedulingObservation>>()
        + size_of::<RetainedProtocolMetadataFacts>() + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<(RetainedProtocolMetadataFacts, usize), RuntimeError>>()
        + size_of::<Ref<'static, MetadataRecordBank>>() + size_of::<RefMut<'static, MetadataRecordBank>>()
        + size_of::<Ref<'static, MetadataAliasBank>>() + size_of::<RefMut<'static, MetadataAliasBank>>()
        + size_of::<Result<Ref<'static, MetadataRecordBank>, BorrowError>>()
        + size_of::<Result<RefMut<'static, MetadataRecordBank>, BorrowMutError>>()
        + size_of::<Result<Ref<'static, MetadataAliasBank>, BorrowError>>()
        + size_of::<Result<RefMut<'static, MetadataAliasBank>, BorrowMutError>>()
        + size_of::<Result<(&PacketNativeRestoredRecord, &PacketNative5UnderlyingRecord, &ContentRef), RuntimeError>>()
}

impl OriginalSourceRestorationObservationAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
    -> usize {
        historical_counter_scratch_data()
    }
}

impl OriginalSourceRestorationObservationAttempt {
    pub(in super::super) fn settled17_once_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<super::super::settled17_once::FirstObservationOnce17, RuntimeError> {
        self.authenticate_original(source, controller, self.binding)?;
        Ok(super::super::settled17_once::FirstObservationOnce17 {
            reserved: self.reserved,
            verified: self.verified,
            binding: self.binding,
        })
    }
}
