//! Retains separately admitted activation signing attempts and failed partials.
//!
//! This owner records two once-started phases under one actual Source/controller
//! pair. It is neither the Core window nor an activation permission; only the
//! private Source wrapper may populate it after consuming a genuine claim.

use super::*;
use std::io;

const PHASES: usize = 2;
const BANKS: usize = 4;

pub(in super::super) struct OriginalSourceRestorationActivationAttempt {
    process: u32,
    thread: std::thread::ThreadId,
    source: *const PacketCompleteSemanticSource,
    controller: *const CnpController,
    binding: blake3::Hash,
    reserved: bool,
    order: ActivationOrder,
    phases: [ActivationPhase; PHASES],
    uploads: [ActivationPhase; 2],
    world_bodies: Option<world_content::WorldUploadBodies>,
    upload_order: upload::UploadOrder,
}

struct ActivationPhase {
    banks: [Vec<u8>; BANKS],
    values: [Option<serde_json::Value>; BANKS],
    native_record: Option<PacketNativeRestoredRecord>,
    underlying: Option<PacketNative5UnderlyingRecord>,
}

impl OriginalSourceRestorationActivationAttempt {
    pub(super) fn minimum_bank_bytes(frame: usize) -> Result<usize, RuntimeError> {
        MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES
            .checked_mul(2)
            .and_then(|bytes| {
                frame
                    .checked_mul(2)
                    .and_then(|frames| bytes.checked_add(frames))
            })
            .and_then(|bytes| bytes.checked_mul(PHASES + 2))
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(super) fn reserve_into(
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        binding: blake3::Hash,
        frame: usize,
        completed: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if completed.is_some() || frame == 0 {
            return Err(RuntimeError::OutstandingObligations);
        }
        Self::minimum_bank_bytes(frame)?;
        // Install the owning slot before the first fallible reservation. Failure
        // retains every already allocated bank and cannot create another attempt.
        *completed = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source,
            controller,
            binding,
            reserved: false,
            order: ActivationOrder::new(),
            phases: std::array::from_fn(|_| ActivationPhase {
                banks: std::array::from_fn(|_| Vec::new()),
                values: std::array::from_fn(|_| None),
                native_record: None,
                underlying: None,
            }),
            uploads: std::array::from_fn(|_| ActivationPhase {
                banks: std::array::from_fn(|_| Vec::new()),
                values: std::array::from_fn(|_| None),
                native_record: None,
                underlying: None,
            }),
            world_bodies: None,
            upload_order: upload::UploadOrder::new(),
        });
        let attempt = completed.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        for phase in attempt.phases.iter_mut().chain(attempt.uploads.iter_mut()) {
            for (bank, maximum) in phase.banks.iter_mut().zip([
                MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
                MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
                frame,
                frame,
            ]) {
                bank.try_reserve_exact(maximum)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
        }
        attempt.reserved = true;
        Ok(())
    }

    pub(super) fn authenticate_original(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        binding: blake3::Hash,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !self.reserved
            || !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || self.binding != binding
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn begin(
        &mut self,
        phase: PacketRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        self.order.begin(phase)
    }

    pub(super) fn retain_value(
        &mut self,
        phase: PacketRestorationActivationPhase,
        index: usize,
        value: serde_json::Value,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.order.authenticate_in_flight(phase)?;
        let phase = &mut self.phases[phase_index(phase)];
        if index >= BANKS {
            return Err(RuntimeError::OutstandingObligations);
        }
        if phase.values[index].is_some() || !phase.banks[index].is_empty() {
            return Err(RuntimeError::OutstandingObligations);
        }
        phase.values[index] = Some(value);
        let value = phase.values[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        canonical::canonical_json_to_writer(
            value,
            &mut BankWriter {
                bytes: &mut phase.banks[index],
                maximum,
            },
        )
        .map_err(|_| RuntimeError::InvalidReceipt)
    }

    pub(in super::super) fn value(
        &self,
        phase: PacketRestorationActivationPhase,
        index: usize,
    ) -> Result<&serde_json::Value, RuntimeError> {
        self.phases[phase_index(phase)]
            .values
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn authenticate_verified(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        if !self.reserved {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.order.authenticate_verified(phase)?;
        if phase == PacketRestorationActivationPhase::WorldActivate {
            self.upload_order.authenticate_complete()?;
        }
        let phase = &self.phases[phase_index(phase)];
        if phase.values.iter().any(Option::is_none) || phase.banks.iter().any(Vec::is_empty) {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }

    pub(super) fn bank(
        &self,
        phase: PacketRestorationActivationPhase,
        index: usize,
    ) -> Result<&[u8], RuntimeError> {
        self.phases[phase_index(phase)]
            .banks
            .get(index)
            .filter(|bank| !bank.is_empty())
            .map(Vec::as_slice)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn retain_native_record(
        &mut self,
        phase: PacketRestorationActivationPhase,
        record: PacketNativeRestoredRecord,
    ) -> Result<(), RuntimeError> {
        self.order.authenticate_in_flight(phase)?;
        let slot = &mut self.phases[phase_index(phase)].native_record;
        if slot.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *slot = Some(record);
        Ok(())
    }

    pub(super) fn native_record(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> Result<&PacketNativeRestoredRecord, RuntimeError> {
        self.phases[phase_index(phase)]
            .native_record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn retain_underlying(
        &mut self,
        phase: PacketRestorationActivationPhase,
        underlying: PacketNative5UnderlyingRecord,
    ) -> Result<(), RuntimeError> {
        self.order.authenticate_in_flight(phase)?;
        let slot = &mut self.phases[phase_index(phase)].underlying;
        if slot.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *slot = Some(underlying);
        Ok(())
    }

    pub(super) fn retain_world_bodies(
        &mut self,
        bodies: world_content::WorldUploadBodies,
    ) -> Result<(), RuntimeError> {
        self.order
            .authenticate_in_flight(PacketRestorationActivationPhase::WorldActivate)?;
        if self.world_bodies.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.world_bodies = Some(bodies);
        Ok(())
    }

    pub(super) fn world_bodies(&self) -> Result<&world_content::WorldUploadBodies, RuntimeError> {
        self.world_bodies
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn begin_upload(
        &mut self,
        role: PacketRestorationActivationUploadRole,
    ) -> Result<(), RuntimeError> {
        self.order
            .authenticate_in_flight(PacketRestorationActivationPhase::WorldActivate)?;
        self.upload_order.begin(role)
    }

    pub(super) fn finish_upload(
        &mut self,
        role: PacketRestorationActivationUploadRole,
    ) -> Result<(), RuntimeError> {
        let slots = &self.uploads[role.ordinal_data()];
        if slots.values.iter().any(Option::is_none) || slots.banks.iter().any(Vec::is_empty) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.upload_order.finish(role)
    }

    pub(super) fn retain_upload_value(
        &mut self,
        role: PacketRestorationActivationUploadRole,
        index: usize,
        value: serde_json::Value,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.upload_order.authenticate_in_flight(role)?;
        let phase = &mut self.uploads[role.ordinal_data()];
        if index >= BANKS || phase.values[index].is_some() || !phase.banks[index].is_empty() {
            return Err(RuntimeError::OutstandingObligations);
        }
        phase.values[index] = Some(value);
        let value = phase.values[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        write_bounded_value_into(value, &mut phase.banks[index], maximum)
    }

    pub(super) fn upload_value(
        &self,
        role: PacketRestorationActivationUploadRole,
        index: usize,
    ) -> Result<&serde_json::Value, RuntimeError> {
        self.uploads[role.ordinal_data()]
            .values
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn finish_verified(
        &mut self,
        phase: PacketRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        self.order.authenticate_in_flight(phase)?;
        if phase == PacketRestorationActivationPhase::WorldActivate {
            self.upload_order.authenticate_complete()?;
        }
        let slots = &self.phases[phase_index(phase)];
        if slots.values.iter().any(Option::is_none)
            || slots.native_record.is_none()
            || slots.underlying.is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.order.finish(phase)
    }
}

fn phase_index(phase: PacketRestorationActivationPhase) -> usize {
    match phase {
        PacketRestorationActivationPhase::Arm => 0,
        PacketRestorationActivationPhase::WorldActivate => 1,
    }
}

// This ledger is DATA beneath the opaque claim. Its production transitions are
// directly testable without constructing a Source, Controller, Window or grant.
struct ActivationOrder {
    started: [bool; PHASES],
    verified: [bool; PHASES],
    failed: bool,
}

impl ActivationOrder {
    fn new() -> Self {
        Self {
            started: [false; PHASES],
            verified: [false; PHASES],
            failed: false,
        }
    }

    fn begin(&mut self, phase: PacketRestorationActivationPhase) -> Result<(), RuntimeError> {
        let index = phase_index(phase);
        if self.failed || self.started[index] || (index == 1 && !self.verified[0]) {
            self.failed = true;
            return Err(RuntimeError::OutstandingObligations);
        }
        // No drop or error path resets this bit. All fallible construction and
        // publication follow it under the same retained original attempt.
        self.started[index] = true;
        Ok(())
    }

    fn authenticate_in_flight(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        let index = phase_index(phase);
        if self.failed || !self.started[index] || self.verified[index] {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    fn authenticate_verified(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> Result<(), RuntimeError> {
        if self.failed
            || !self.verified[phase_index(phase)]
            || (phase_index(phase) == 0 && self.started[1])
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    fn finish(&mut self, phase: PacketRestorationActivationPhase) -> Result<(), RuntimeError> {
        if self.authenticate_in_flight(phase).is_err() {
            self.failed = true;
            return Err(RuntimeError::OutstandingObligations);
        }
        self.verified[phase_index(phase)] = true;
        Ok(())
    }
}

struct BankWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl io::Write for BankWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let complete = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if complete > self.maximum || complete > self.bytes.capacity() {
            // Source maps this kind to its fixed RuntimeError; constructing a
            // boxed diagnostic here would add an unquoted failure allocation.
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OriginalSourceRestorationActivationAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn allocated_bank_bytes_with_error<
        E: StorageError,
    >(
        &self,
    ) -> Result<usize, E> {
        let bodies = self
            .world_bodies
            .as_ref()
            .map(|bodies| {
                bodies
                    .coordinator
                    .bytes
                    .capacity()
                    .checked_add(bodies.manifest.bytes.capacity())
                    .ok_or_else(|| E::limit("activation world body capacity overflow"))
            })
            .transpose()?
            .unwrap_or(0);
        self.phases
            .iter()
            .chain(self.uploads.iter())
            .try_fold(bodies, |total, phase| {
                phase.banks.iter().try_fold(total, |total, bank| {
                    total
                        .checked_add(bank.capacity())
                        .ok_or_else(|| E::limit("activation signing bank capacity overflow"))
                })
            })
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn native_evidence_backing_bytes_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::sum_with_error;
        // Upload slots never accept native receipt/model owners. Refuse an
        // unknown future state rather than silently omit it from this walk.
        if self
            .uploads
            .iter()
            .any(|phase| phase.native_record.is_some() || phase.underlying.is_some())
        {
            return Err(E::unknown("upload slot unexpectedly owns native evidence"));
        }
        self.phases.iter().try_fold(0usize, |bytes, phase| {
            let Some(record) = phase.native_record.as_ref() else {
                // The underlying owner is inserted only after its receipt.
                if phase.underlying.is_some() {
                    return Err(E::unknown("activation evidence owner lacks its receipt"));
                }
                return Ok(bytes);
            };
            let facts = restoration_activation_retained_native_evidence_data(
                record, phase.underlying.as_ref(),
            ).map_err(E::unknown)?;
            sum_with_error::<E, _>([
                bytes,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                    &facts, maximum,
                )?,
            ], maximum)
        })
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn normalized_value_bytes_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
            sum_with_error, value_storage_with_error,
        };
        use crate::node_contract::RuntimeOwnedStorage;
        let bodies =
            self.world_bodies
                .as_ref()
                .map(|bodies| {
                    let coordinator =
                        bodies.coordinator.reference.owned_storage().map_err(|_| {
                            E::limit("activation coordinator reference census failed")
                        })?;
                    let manifest = bodies
                        .manifest
                        .reference
                        .owned_storage()
                        .map_err(|_| E::limit("activation manifest reference census failed"))?;
                    sum_with_error::<E, _>([coordinator, manifest], maximum)
                })
                .transpose()?
                .unwrap_or(0);
        self.phases
            .iter()
            .chain(self.uploads.iter())
            .try_fold(bodies, |total, phase| {
                phase
                    .values
                    .iter()
                    .flatten()
                    .try_fold(total, |total, value| {
                        sum_with_error::<E, _>(
                            [total, value_storage_with_error::<E>(value, 0, maximum)?],
                            maximum,
                        )
                    })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn actual_phase_ledger_requires_arm_then_once_world_without_failure_reopening() {
        use PacketRestorationActivationPhase::{Arm, WorldActivate};
        let mut completed = ActivationOrder::new();
        completed.begin(Arm).unwrap();
        completed.finish(Arm).unwrap();
        completed.begin(WorldActivate).unwrap();
        assert!(completed.authenticate_verified(Arm).is_err());
        completed.finish(WorldActivate).unwrap();
        completed.authenticate_verified(WorldActivate).unwrap();
        assert!(completed.begin(WorldActivate).is_err());
        assert!(completed.authenticate_verified(WorldActivate).is_err());

        let mut skipped = ActivationOrder::new();
        assert!(skipped.begin(WorldActivate).is_err());
        assert!(skipped.begin(Arm).is_err());
        assert!(skipped.finish(WorldActivate).is_err());

        let mut partial = ActivationOrder::new();
        partial.begin(Arm).unwrap();
        assert!(partial.begin(Arm).is_err());
        assert!(partial.finish(Arm).is_err());
        assert!(partial.begin(WorldActivate).is_err());
    }

    #[test]
    fn bounded_canonical_writer_retains_prefix_and_never_grows_after_refusal() {
        let mut bytes = Vec::with_capacity(8);
        let original_capacity = bytes.capacity();
        let mut writer = BankWriter {
            bytes: &mut bytes,
            maximum: 5,
        };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"def").is_err());
        assert_eq!(writer.bytes.as_slice(), b"abc");
        assert_eq!(writer.bytes.capacity(), original_capacity);
        writer.write_all(b"de").unwrap();
        assert_eq!(writer.bytes.as_slice(), b"abcde");
        assert!(writer.write_all(b"f").is_err());
        assert_eq!(writer.bytes.as_slice(), b"abcde");
        assert_eq!(writer.bytes.capacity(), original_capacity);
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<OriginalSourceRestorationActivationAttempt>()
        + size_of::<Option<OriginalSourceRestorationActivationAttempt>>()
        + size_of::<ActivationPhase>()
        + size_of::<ActivationOrder>()
        + size_of::<BankWriter<'static>>()
        + size_of::<std::slice::IterMut<'static, ActivationPhase>>()
        + size_of::<
            std::iter::Zip<
                std::slice::IterMut<'static, Vec<u8>>,
                std::array::IntoIter<usize, BANKS>,
            >,
        >()
        + size_of::<std::slice::Iter<'static, ActivationPhase>>()
        + size_of::<
            std::iter::Chain<
                std::slice::Iter<'static, ActivationPhase>,
                std::slice::Iter<'static, ActivationPhase>,
            >,
        >()
        + size_of::<
            std::iter::Chain<
                std::slice::IterMut<'static, ActivationPhase>,
                std::slice::IterMut<'static, ActivationPhase>,
            >,
        >()
        + size_of::<Option<&'static world_content::WorldUploadBodies>>()
        + size_of::<Result<&'static world_content::WorldUploadBodies, RuntimeError>>()
        + size_of::<Result<Option<usize>, RuntimeError>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<std::slice::Iter<'static, Vec<u8>>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<serde_json::Value>>>>()
        + size_of::<Option<&'static PacketNativeRestoredRecord>>()
        + size_of::<Option<&'static PacketNative5UnderlyingRecord>>()
        + size_of::<Result<&'static serde_json::Value, RuntimeError>>()
        + size_of::<Result<&'static PacketNativeRestoredRecord, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<usize, std::io::Error>>()
}

// This helper remains inside the defining owner module so every caller uses the
// same fixed-capacity writer and preserves its already written prefix on error.
pub(super) fn write_bounded_value_into(
    value: &serde_json::Value,
    bytes: &mut Vec<u8>,
    maximum: usize,
) -> Result<(), RuntimeError> {
    if !bytes.is_empty() || bytes.capacity() < maximum {
        return Err(RuntimeError::OutstandingObligations);
    }
    canonical::canonical_json_to_writer(value, &mut BankWriter { bytes, maximum })
        .map_err(|_| RuntimeError::InvalidReceipt)
}

/// Lends all original Source activation banks, values and native partials.
pub(crate) struct SourceRestorationActivationHistoryData<'a> {
    original: &'a OriginalSourceRestorationActivationAttempt,
    records: &'a std::cell::RefCell<
        crucible_node_transport::retained_metadata::records::MetadataRecordBank,
    >,
    aliases: &'a std::cell::RefCell<
        crucible_node_transport::retained_metadata::aliases::MetadataAliasBank,
    >,
}

impl OriginalSourceRestorationActivationAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_data<'a>(
        &'a self,
        records: &'a std::cell::RefCell<
            crucible_node_transport::retained_metadata::records::MetadataRecordBank,
        >,
        aliases: &'a std::cell::RefCell<
            crucible_node_transport::retained_metadata::aliases::MetadataAliasBank,
        >,
    ) -> SourceRestorationActivationHistoryData<'a> {
        SourceRestorationActivationHistoryData {
            original: self,
            records,
            aliases,
        }
    }

    /// Reports actual metadata demand before the capture bank is allocated.
    ///
    /// # Errors
    /// Refuses a model without its owner, overflow or unsupported metadata.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_metadata_demand_data(
        &self,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        let mut records = 0usize;
        let mut aliases = 0usize;
        let mut transient = 0usize;
        for phase in self.phases.iter().chain(&self.uploads) {
            if phase.underlying.is_some() && phase.native_record.is_none() {
                return Err(RuntimeError::InvalidReceipt);
            }
            let Some(record) = &phase.native_record else {
                continue;
            };
            let facts = crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_retained_native_evidence_data(
                record, phase.underlying.as_ref(),
            ).map_err(|_| RuntimeError::ResourceLimit)?;
            // Complete each serialized owner before reusing the temporary banks.
            records = records.max(facts.capacity_records);
            aliases = aliases.max(facts.shared_backing_views);
            transient = transient.checked_add(crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_historical_native_evidence_transient_bytes_data(
                record, phase.underlying.as_ref(),
            ).map_err(|_| RuntimeError::ResourceLimit)?).ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok((records, aliases, transient))
    }
}

struct HistoricalPhases<'a>(
    &'a [ActivationPhase; 2],
    &'a SourceRestorationActivationHistoryData<'a>,
);
struct HistoricalPhase<'a>(
    &'a ActivationPhase,
    &'a SourceRestorationActivationHistoryData<'a>,
);
struct HistoricalNativeCapacities<'a>(
    &'a ActivationPhase,
    &'a SourceRestorationActivationHistoryData<'a>,
);
struct HistoricalUnderlying<'a>(&'a PacketNative5UnderlyingRecord);

#[derive(serde::Serialize)]
struct HistoricalWorldBodies<'a> {
    coordinator: &'a crate::node_scheduling::InputPayload,
    manifest: &'a crate::node_scheduling::InputPayload,
    coordinator_capacities:
        crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows<
            'a,
            crate::node_scheduling::InputPayload,
        >,
    manifest_capacities:
        crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows<
            'a,
            crate::node_scheduling::InputPayload,
        >,
}

impl serde::Serialize for HistoricalPhases<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut values = serializer.serialize_seq(Some(2))?;
        for phase in self.0 {
            values.serialize_element(&HistoricalPhase(phase, self.1))?;
        }
        values.end()
    }
}

impl serde::Serialize for HistoricalPhase<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows;
        use serde::ser::SerializeStruct;
        let ActivationPhase {
            banks,
            values,
            native_record,
            underlying,
        } = self.0;
        let mut value = serializer.serialize_struct("SourceActivationPhaseHistory", 7)?;
        value.serialize_field("banks", banks)?;
        value.serialize_field(
            "bank_capacities",
            &OriginalRestoredOwnerCapacityRows(banks.as_slice()),
        )?;
        value.serialize_field("values", values)?;
        value.serialize_field(
            "value_capacities",
            &OriginalRestoredOwnerCapacityRows(values.as_slice()),
        )?;
        value.serialize_field(
            "native_capacities",
            &HistoricalNativeCapacities(self.0, self.1),
        )?;
        value.serialize_field("native_record", native_record)?;
        value.serialize_field("underlying", &underlying.as_ref().map(HistoricalUnderlying))?;
        value.end()
    }
}

impl serde::Serialize for HistoricalNativeCapacities<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};
        let Some(record) = &self.0.native_record else {
            return serializer.serialize_none();
        };
        {
            let mut records = self.1.records.try_borrow_mut().map_err(S::Error::custom)?;
            let mut aliases = self.1.aliases.try_borrow_mut().map_err(S::Error::custom)?;
            let before = crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_retained_native_evidence_data(
                record, self.0.underlying.as_ref(),
            ).map_err(S::Error::custom)?;
            let after = crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_record_native_evidence_metadata_data(
                record, self.0.underlying.as_ref(), &mut records, &mut aliases,
            ).map_err(S::Error::custom)?;
            if before != after {
                return Err(S::Error::custom("Source activation native owner changed"));
            }
        }
        let records = self.1.records.try_borrow().map_err(S::Error::custom)?;
        let aliases = self.1.aliases.try_borrow().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("SourceActivationNativeCapacities", 5)?;
        value.serialize_field("record_capacity", &records.capacity_rows())?;
        value.serialize_field("record_maximum", &records.maximum_rows())?;
        value.serialize_field("records", &*records)?;
        value.serialize_field("alias_capacities", &aliases.capacity_rows())?;
        value.serialize_field("aliases", &*aliases)?;
        value.end()
    }
}

impl serde::Serialize for HistoricalUnderlying<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("SourceActivationUnderlying", 2)?;
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

impl serde::Serialize for SourceRestorationActivationHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows;
        use serde::ser::{Error, SerializeStruct};
        let OriginalSourceRestorationActivationAttempt {
            process: _,
            thread: _,
            source: _,
            controller: _,
            binding,
            reserved,
            order,
            phases,
            uploads,
            world_bodies,
            upload_order,
        } = self.original;
        self.original
            .historical_metadata_demand_data()
            .map_err(S::Error::custom)?;
        let ActivationOrder {
            started,
            verified,
            failed,
        } = order;
        let bodies = world_bodies.as_ref().map(|bodies| {
            let world_content::WorldUploadBodies {
                coordinator,
                manifest,
            } = bodies;
            HistoricalWorldBodies {
                coordinator,
                manifest,
                coordinator_capacities: OriginalRestoredOwnerCapacityRows(coordinator),
                manifest_capacities: OriginalRestoredOwnerCapacityRows(manifest),
            }
        });
        let mut value = serializer.serialize_struct("SourceActivationHistory", 10)?;
        value.serialize_field("schema", "source-private.source-activation-history/1")?;
        value.serialize_field("binding", binding.as_bytes())?;
        value.serialize_field("reserved", reserved)?;
        value.serialize_field("phase_started", started)?;
        value.serialize_field("phase_verified", verified)?;
        value.serialize_field("failed", failed)?;
        value.serialize_field("phases", &HistoricalPhases(phases, self))?;
        value.serialize_field("uploads", &HistoricalPhases(uploads, self))?;
        value.serialize_field("world_bodies", &bodies)?;
        value.serialize_field("upload_order", &upload_order.historical_data())?;
        value.end()
    }
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
-> usize {
    use crucible_node_transport::retained_metadata::{
        aliases::MetadataAliasBank, records::MetadataRecordBank,
    };
    use std::cell::{BorrowError, BorrowMutError, Ref, RefMut};
    crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data()
        + size_of::<SourceRestorationActivationHistoryData<'static>>()
        + size_of::<HistoricalPhases<'static>>() + size_of::<HistoricalPhase<'static>>()
        + size_of::<HistoricalNativeCapacities<'static>>()
        + size_of::<HistoricalUnderlying<'static>>() + size_of::<Option<HistoricalUnderlying<'static>>>()
        + size_of::<HistoricalWorldBodies<'static>>() + size_of::<Option<HistoricalWorldBodies<'static>>>()
        + size_of::<std::iter::Chain<std::slice::Iter<'static, ActivationPhase>, std::slice::Iter<'static, ActivationPhase>>>()
        + size_of::<Result<(usize, usize, usize), RuntimeError>>()
        + size_of::<Ref<'static, MetadataRecordBank>>() + size_of::<RefMut<'static, MetadataRecordBank>>()
        + size_of::<Ref<'static, MetadataAliasBank>>() + size_of::<RefMut<'static, MetadataAliasBank>>()
        + size_of::<Result<Ref<'static, MetadataRecordBank>, BorrowError>>()
        + size_of::<Result<RefMut<'static, MetadataRecordBank>, BorrowMutError>>()
        + size_of::<Result<Ref<'static, MetadataAliasBank>, BorrowError>>()
        + size_of::<Result<RefMut<'static, MetadataAliasBank>, BorrowMutError>>()
        + upload::UploadOrder::historical_counter_scratch_data()
}

impl OriginalSourceRestorationActivationAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
    -> usize {
        historical_counter_scratch_data()
    }
}

impl OriginalSourceRestorationActivationAttempt {
    pub(in super::super) fn settled17_once_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<super::super::settled17_once::ActivationOnce17, RuntimeError> {
        self.authenticate_original(source, controller, self.binding)?;
        self.authenticate_verified(PacketRestorationActivationPhase::WorldActivate)?;
        let (uploads_next, upload_in_flight, upload_failed) =
            self.upload_order.settled17_once_data();
        Ok(super::super::settled17_once::ActivationOnce17 {
            reserved: self.reserved,
            started: self.order.started,
            verified: self.order.verified,
            failed: self.order.failed,
            uploads_next,
            upload_in_flight,
            upload_failed,
        })
    }
}
