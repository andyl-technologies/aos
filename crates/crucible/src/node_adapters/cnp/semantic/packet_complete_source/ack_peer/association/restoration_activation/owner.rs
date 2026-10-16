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

    pub(super) fn value(
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
