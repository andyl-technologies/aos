//! Retains the genuine settled17 prefix, launch8 and every partial write.
//!
//! No caller row or purpose selects this entry. It requires the consumed Core
//! settled member and same completed Source15. The old nested Source and boot7
//! grammars remain unchanged; this writer grants no Endpoint or Capture action.

use super::*;
use crucible_node_provider::reference_packet::service::native_startup::{
    ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES, PacketNativeInvocationPreambleData,
    PacketNativeSettledPreambleData, PacketNativeSuffixPreambleData,
    encode_original_native_settled_preamble_data, original_native_settled_launch_identity_data,
    write_original_native_settled_launch_data,
};

/// Owns the new exact wire banks and sticky partial-write cursors.
///
/// The caller must retain this owner through refusal. It contains the actual
/// private key on wire and must never be logged or treated as action evidence.
#[must_use = "retain original wire banks and partial progress through refusal"]
pub struct PacketCompleteNativeRestoredSettledStartupWire {
    process: u32,
    thread: ThreadId,
    birth_id: [u8; 32],
    preamble: [u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES],
    preamble_written: usize,
    launch: Vec<u8>,
    launch_written: usize,
    boot: Option<PacketCompleteAckPeerBootFrame>,
    prepared: bool,
}

impl PacketCompleteNativeRestoredSettledStartupWire {
    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    /// Observes actual nested capacities without decoding or allocating.
    ///
    /// # Errors
    /// Refuses foreign origin, unavailable boot custody or complete overflow.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        let boot = self
            .boot
            .as_ref()
            .map(|boot| boot.retained_requested_storage_precredit_data(maximum))
            .transpose()?
            .unwrap_or(0);
        self.launch
            .capacity()
            .checked_add(boot)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Writes the same consumed settled member in fixed prefix/launch/boot order.
    ///
    /// # Errors
    /// Refuses a changed member, unprepared bank or writer failure. Successful
    /// partial writes remain recorded and cannot be rewound by another owner.
    pub fn write_original(
        &mut self,
        material: &PacketCompleteAckPeerBootMaterial<'_>,
        writer: &mut impl Write,
    ) -> Result<(), OperationFailure> {
        self.origin()
            .map_err(|_| refused("restored settled wire foreign origin"))?;
        material.authenticate_original()?;
        let state = material
            .original
            .native_startup
            .as_ref()
            .ok_or_else(|| refused("restored settled member absent"))?;
        let suffix = state
            .member
            .suffix
            .as_ref()
            .ok_or_else(|| refused("restored settled reservation absent"))?;
        let settled = suffix
            .settled_data(material.source)
            .map_err(|_| refused("restored settled member differs"))?
            .ok_or_else(|| refused("restored settled carrier absent"))?;
        settled
            .authenticate_wire_in_progress_data()
            .map_err(|_| refused("restored settled member differs"))?;
        if !state.complete || !self.prepared || material.birth_id()? != &self.birth_id {
            return Err(refused("restored settled wire incomplete or foreign"));
        }
        write_bank(&self.preamble, &mut self.preamble_written, material, writer)?;
        write_bank(&self.launch, &mut self.launch_written, material, writer)?;
        self.boot
            .as_mut()
            .ok_or_else(|| refused("restored settled boot absent"))?
            .write_original(material, writer)?;
        material.authenticate_original()?;
        // A completed host write is only a prerequisite. The native17 reader
        // must still authenticate its own receipt, Prepare inputs and Observe.
        settled
            .complete_wire_data()
            .map_err(|_| refused("restored settled publication incomplete"))
    }
}

struct Limited<'a> {
    bank: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for Limited<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .bank
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        if end > self.bank.capacity() {
            return Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory));
        }
        self.bank.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl PacketCompleteAckPeerBootMaterial<'_> {
    /// Retains prefix17, original launch8 and private boot7 before any Child.
    ///
    /// The same source-bound purpose and typed launch are requoted by Core before
    /// this entry. Every bank and partial encoding remains in `completed` if a
    /// later allocation, encoding or final currentness check refuses.
    ///
    /// # Errors
    /// Refuses occupied output, another actual launch/target, missing genuine
    /// member, changed wrapper identity, exhausted fixed capacity or currency.
    pub fn prepare_original_restored_settled_wire_into(
        &self,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        completed: &mut Option<PacketCompleteNativeRestoredSettledStartupWire>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original()?;
        if completed.is_some() {
            return Err(refused("restored settled wire slot occupied"));
        }
        self.source
            .authenticate_native_launch_data(launch)
            .map_err(|_| refused("restored settled launch differs"))?;
        let state = self
            .original
            .native_startup
            .as_ref()
            .ok_or_else(|| refused("restored settled member absent"))?;
        if !state.complete {
            return Err(refused("restored settled Source incomplete"));
        }
        let purpose = state
            .original_invocation_data()
            .map_err(|_| refused("restored settled Source binding"))?
            .ok_or_else(|| refused("restored settled Source edition absent"))?;
        purpose
            .authenticate_target_data(launch)
            .map_err(|_| refused("restored settled target differs"))?;
        let suffix = state
            .member
            .suffix
            .as_ref()
            .ok_or_else(|| refused("restored settled member absent"))?;
        suffix
            .authenticate_source_data(self.source)
            .map_err(|_| refused("restored settled member differs"))?;
        if !self
            .source
            .is_original_restored_settled_capture_declaration_data()
            .map_err(|_| refused("restored settled declaration unavailable"))?
        {
            return Err(refused("restored settled declaration absent"));
        }
        let settled = suffix
            .settled_data(self.source)
            .map_err(|_| refused("restored settled member differs"))?
            .ok_or_else(|| refused("restored settled carrier absent"))?;
        let capture = settled.carrier_data();
        let reservation = suffix.reservation_data();
        let identity = original_native_settled_launch_identity_data(
            &purpose,
            canonical_launch5,
            &reservation,
            settled.existing_rows_data(),
            capture,
        )
        .map_err(|_| refused("restored settled launch identity"))?;
        if identity != settled.launch_identity_data() || identity.encoded_bytes > 1024 * 1024 {
            return Err(refused("restored settled original launch differs"));
        }
        // Spend the same Source occurrence before retaining any partial bank.
        settled
            .begin_wire_data()
            .map_err(|_| refused("restored settled wire already attempted"))?;
        *completed = Some(PacketCompleteNativeRestoredSettledStartupWire {
            process: std::process::id(),
            thread: std::thread::current().id(),
            birth_id: self.original.birth_id,
            preamble: [0; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES],
            preamble_written: 0,
            launch: Vec::new(),
            launch_written: 0,
            boot: None,
            prepared: false,
        });
        let wire = completed
            .as_mut()
            .ok_or_else(|| refused("restored settled wire absent"))?;
        let rows = state.member.rows;
        wire.preamble = encode_original_native_settled_preamble_data(
            &PacketNativeSettledPreambleData {
                suffix: PacketNativeSuffixPreambleData {
                    invocation: PacketNativeInvocationPreambleData {
                        controller_pid: launch.controller_pid.get(),
                        controller_uid: launch.controller_uid.get(),
                        launch_bytes: u32::try_from(identity.encoded_bytes)
                            .map_err(|_| refused("restored settled launch extent"))?,
                        maximum_boot_bytes: u32::try_from(state.member.maximum_boot_bytes)
                            .map_err(|_| refused("restored settled boot extent"))?,
                        birth_id: self.original.birth_id,
                        launch_digest: identity.raw_digest,
                        source_digest: *blake3::hash(&self.original.source_birth).as_bytes(),
                        registration_digest: *blake3::hash(
                            &self.original.expected_host_registration,
                        )
                        .as_bytes(),
                        private_launch_digest: *blake3::hash(
                            self.original.private_launch.as_str().as_bytes(),
                        )
                        .as_bytes(),
                        private_bootstrap: rows.private_bootstrap,
                        native_birth: rows.native_birth,
                        restore_prepare: rows.restore_prepare,
                    },
                    suffix_reservation: reservation,
                },
                capture: *capture,
            },
            &self.original.key,
        )
        .map_err(|_| refused("restored settled prefix DATA"))?;
        let maximum = identity
            .encoded_bytes
            .checked_add(4)
            .ok_or_else(|| refused("restored settled wire extent"))?;
        wire.launch
            .try_reserve_exact(maximum)
            .map_err(|_| refused("restored settled bank unavailable"))?;
        if wire.launch.capacity() > maximum {
            return Err(refused("restored settled bank capacity widened"));
        }
        let length = u32::try_from(identity.encoded_bytes)
            .map_err(|_| refused("restored settled body extent"))?;
        wire.launch.extend_from_slice(&length.to_be_bytes());
        write_original_native_settled_launch_data(
            &purpose,
            canonical_launch5,
            &reservation,
            settled.existing_rows_data(),
            capture,
            &mut Limited {
                bank: &mut wire.launch,
                maximum,
            },
        )
        .map_err(|_| refused("restored settled retained encoding refused"))?;
        if wire.launch.len() != maximum
            || blake3::hash(&wire.launch[4..]).as_bytes() != &identity.raw_digest
        {
            return Err(refused("restored settled constructed bank differs"));
        }
        self.prepare_private_boot_frame_into(&mut wire.boot)?;
        self.authenticate_original()?;
        wire.prepared = true;
        Ok(())
    }
}

// One new refusal can coexist with every retained partial bank. The longest
// literal bounds ordinary copying; the defining diagnostic bound also covers
// the private initial-operation prefix without relying on that TLS mode.
pub(super) fn refusal_storage_data() -> usize {
    use crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics;
    std::mem::size_of::<OperationFailure>()
        + 4 * ("restored settled wire incomplete or foreign".len()
            + OriginalInitialLifecycleDiagnostics::requested_bytes())
        + 256
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn counter_scratch_data()
-> usize {
    use std::mem::size_of;
    refusal_storage_data()
        + size_of::<PacketCompleteNativeRestoredSettledStartupWire>()
        + size_of::<Option<PacketCompleteNativeRestoredSettledStartupWire>>()
        + size_of::<&mut Option<PacketCompleteNativeRestoredSettledStartupWire>>()
        + size_of::<Option<&mut PacketCompleteNativeRestoredSettledStartupWire>>()
        + size_of::<Result<&mut PacketCompleteNativeRestoredSettledStartupWire, OperationFailure>>()
        + size_of::<Option<&PacketCompleteAckPeerBootFrame>>()
        + size_of::<&PacketCompleteAckPeerBootFrame>()
        + size_of::<Result<&PacketCompleteAckPeerBootFrame, OperationFailure>>()
        + size_of::<Option<&mut PacketCompleteAckPeerBootFrame>>()
        + size_of::<Result<&mut PacketCompleteAckPeerBootFrame, OperationFailure>>()
        + size_of::<Result<&crate::node_admission::OriginalRestoredSuffixStartupMember, OperationFailure>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<Option<usize>, RuntimeError>>()
        + size_of::<Option<Result<usize, RuntimeError>>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<u32, OperationFailure>>()
        + size_of::<Limited<'static>>()
        + size_of::<PacketNativeSuffixPreambleData>()
        + size_of::<PacketNativeSettledPreambleData>()
        + size_of::<&crate::node_admission::OriginalRestoredSettledStartupMember>()
        + size_of::<Option<&crate::node_admission::OriginalRestoredSettledStartupMember>>()
        + size_of::<Result<Option<&crate::node_admission::OriginalRestoredSettledStartupMember>,RuntimeError>>()
        + size_of::<Result<&crate::node_admission::OriginalRestoredSettledStartupMember,OperationFailure>>()
        + size_of::<&crucible_node_provider::reference_packet::service::native_startup::PacketRestoredSettledNativeCarrierData>()
        + size_of::<crucible_node_provider::reference_packet::service::native_startup::PacketRestoredSettledNativeCarrierData>()
        + size_of::<Result<[u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES], crucible_node_provider::ProviderError>>()
        + size_of::<crucible_node_provider::reference_packet::service::native_startup::PacketNativeSuffixLaunchIdentityData>()
        + size_of::<Result<crucible_node_provider::reference_packet::service::native_startup::PacketNativeSuffixLaunchIdentityData, crucible_node_provider::ProviderError>>()
        + size_of::<crucible_node_provider::reference_packet::service::native_startup::PacketRestoredSuffixReservationData>()
        + size_of::<&crate::node_admission::OriginalRestoredSuffixStartupMember>()
        + size_of::<Option<&crate::node_admission::OriginalRestoredSuffixStartupMember>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<[u8; 4]>()
        + size_of::<std::io::Result<usize>>()
        + size_of::<std::io::Result<()>>()
        + size_of::<crucible_node_provider::reference_packet::service::native_startup::PacketNativeInvocationPurposeData>()
        + size_of::<Result<Option<crucible_node_provider::reference_packet::service::native_startup::PacketNativeInvocationPurposeData>, RuntimeError>>()
        + size_of::<&super::super::native_startup::OriginalNativeStartupFinalization>()
        + size_of::<Option<&super::super::native_startup::OriginalNativeStartupFinalization>>()
        + size_of::<Result<&super::super::native_startup::OriginalNativeStartupFinalization, OperationFailure>>()
        + size_of::<&PacketCompleteAckPeerBootMaterial<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&[u8]>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<u32, std::num::TryFromIntError>>()
        + 4 * size_of::<usize>()
        + crucible_node_provider::reference_packet::service::native_startup::original_native_settled_carrier_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_limited_writer_keeps_partial_bank_on_exact_and_short_refusal() {
        let mut bank = Vec::with_capacity(7);
        let pointer = bank.as_ptr();
        {
            let mut writer = Limited {
                bank: &mut bank,
                maximum: 7,
            };
            writer.write_all(b"prefix").unwrap();
            assert!(writer.write_all(b"xx").is_err());
            assert_eq!(writer.bank.as_slice(), b"prefix");
            writer.write_all(b"x").unwrap();
            assert!(writer.write_all(b"!").is_err());
        }
        assert_eq!(bank.as_slice(), b"prefixx");
        assert_eq!(bank.as_ptr(), pointer);
        assert_eq!(bank.capacity(), 7);
    }
}
