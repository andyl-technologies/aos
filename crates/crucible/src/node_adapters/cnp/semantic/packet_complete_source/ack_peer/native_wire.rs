//! Retains the exact prefix, launch and boot write progress of one native birth.
//!
//! The version-fourteen prefix is sent first, followed by the original canonical
//! launch frame and boot6 frame. No public constructor or raw-byte setter exists.
//! Failed preparation/writes leave the same owners and cursors in the caller's
//! slot; their receipt never supplies semantic, activation or capture rights.

use super::super::frame::PacketCompleteAckPeerBootFrame;
use super::*;
use crate::node_adapters::cnp::CnpSemanticSource;
use crate::node_contract::RuntimeError;
use crucible_node_provider::reference_packet::service::{
    PacketNative5SourceLaunch,
    native_startup::{
        ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES, PacketNativeStartupPreambleData,
        encode_original_native_startup_preamble_data,
    },
};
use std::io::Write;

#[path = "native_wire/import18.rs"]
mod import18;
pub use import18::PacketCompleteNativeImport18StartupWire;

/// Owns one original native startup wire sequence and every partial write.
///
/// The bytes contain the original private key and must never be logged.
/// The same independently supervised writer and Child remain caller-owned.
pub struct PacketCompleteNativeStartupWire {
    process: u32,
    thread: ThreadId,
    birth_id: [u8; 32],
    preamble: [u8; ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES],
    preamble_written: usize,
    launch: Vec<u8>,
    launch_written: usize,
    boot: Option<PacketCompleteAckPeerBootFrame>,
    prepared: bool,
}

impl PacketCompleteNativeStartupWire {
    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    /// Observes actual nested banks without hashing, I/O or erased callbacks.
    ///
    /// The containing holder separately charges this type's inline layout.
    ///
    /// # Errors
    /// Refuses a foreign actor, widened capacity or arithmetic overflow.
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

    /// Writes the same admitted prefix, launch and boot in their fixed order.
    ///
    /// # Errors
    /// Refuses incomplete preparation, another birth, revoked Source member or
    /// a writer error. Every successful short write remains recorded.
    pub fn write_original(
        &mut self,
        material: &PacketCompleteAckPeerBootMaterial<'_>,
        writer: &mut impl Write,
    ) -> Result<(), OperationFailure> {
        self.origin()
            .map_err(|_| refused("native startup wire foreign origin"))?;
        material.authenticate_original()?;
        if material
            .original
            .native_startup
            .as_ref()
            .is_some_and(|state| state.member.suffix.is_some())
        {
            return Err(refused(
                "restored suffix requires its distinct original writer",
            ));
        }
        if !self.prepared || material.birth_id()? != &self.birth_id {
            return Err(refused("native startup wire original association differs"));
        }
        write_bank(&self.preamble, &mut self.preamble_written, material, writer)?;
        write_bank(&self.launch, &mut self.launch_written, material, writer)?;
        self.boot
            .as_mut()
            .ok_or_else(|| refused("native startup boot frame absent"))?
            .write_original(material, writer)?;
        material.authenticate_original()
    }
}

fn write_bank(
    bytes: &[u8],
    written: &mut usize,
    material: &PacketCompleteAckPeerBootMaterial<'_>,
    writer: &mut impl Write,
) -> Result<(), OperationFailure> {
    while *written < bytes.len() {
        material.authenticate_startup_member()?;
        material.original.ensure_origin()?;
        match writer.write(&bytes[*written..]) {
            Ok(0) => return Err(refused("native startup writer made no progress")),
            Ok(count) if count <= bytes.len() - *written => *written += count,
            Ok(_) => return Err(refused("native startup writer extent changed")),
            Err(_) => return Err(refused("native startup original writer refused")),
        }
    }
    material.authenticate_original()
}

impl PacketCompleteAckPeerBootMaterial<'_> {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn original_private_boot_schema_data(
        &self,
    ) -> Result<&'static str, OperationFailure> {
        self.authenticate_startup_member()?;
        if self.original.native_import18.is_some() {
            return Err(refused(
                "import18 requires its distinct private boot writer",
            ));
        }
        if let Some(state) = &self.original.native_startup {
            if state
                .original_invocation_data()
                .map_err(|_| refused("native invocation Source binding"))?
                .is_some()
            {
                return Ok(crucible_node_provider::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA);
            }
        }
        Ok(if self.original.native_startup.is_some() {
            crucible_node_provider::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA
        } else {
            "source-owned.packet-canonical-ack-private-boot/5"
        })
    }

    /// Prepares the exact native sequence under this Source's finalized member.
    ///
    /// The caller stores the result before any reservation or Child effect and
    /// retains it beside the actual original writer/reservation through failure.
    ///
    /// # Errors
    /// Refuses another launch, unfinalized/revoked admission, occupied result,
    /// allocation failure or encoded banks above the admitted closed geometry.
    pub fn prepare_original_native_startup_wire_into(
        &self,
        launch: &PacketNative5SourceLaunch,
        encoded_launch: &[u8],
        completed: &mut Option<PacketCompleteNativeStartupWire>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original()?;
        if completed.is_some() {
            return Err(refused("native startup wire slot occupied"));
        }
        self.source
            .authenticate_native_launch_data(launch)
            .map_err(|_| refused("native startup launch differs from original Source"))?;
        let finalized = self
            .original
            .native_startup
            .as_ref()
            .ok_or_else(|| refused("native startup allocation not finalized"))?;
        if finalized
            .original_invocation_data()
            .map_err(|_| refused("native invocation Source binding"))?
            .is_some()
        {
            return Err(refused("invocation15 requires its original wire entry"));
        }
        if finalized.member.suffix.is_some() {
            return Err(refused(
                "restored suffix requires its distinct original wire entry",
            ));
        }
        if !finalized.complete
            || blake3::hash(encoded_launch).as_bytes() != &finalized.member.launch_digest
        {
            return Err(refused(
                "native startup encoded launch differs from admitted original",
            ));
        }
        *completed = Some(PacketCompleteNativeStartupWire {
            process: std::process::id(),
            thread: std::thread::current().id(),
            birth_id: self.original.birth_id,
            preamble: [0; ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES],
            preamble_written: 0,
            launch: Vec::new(),
            launch_written: 0,
            boot: None,
            prepared: false,
        });
        let wire = completed
            .as_mut()
            .ok_or_else(|| refused("native startup wire slot absent"))?;
        let rows = finalized.member.rows;
        wire.preamble = encode_original_native_startup_preamble_data(
            &PacketNativeStartupPreambleData {
                controller_pid: launch.controller_pid.get(),
                controller_uid: launch.controller_uid.get(),
                launch_bytes: u32::try_from(encoded_launch.len())
                    .map_err(|_| refused("native startup launch extent"))?,
                maximum_boot_bytes: u32::try_from(finalized.member.maximum_boot_bytes)
                    .map_err(|_| refused("native startup boot extent"))?,
                birth_id: self.original.birth_id,
                launch_digest: finalized.member.launch_digest,
                source_digest: *blake3::hash(&self.original.source_birth).as_bytes(),
                registration_digest: *blake3::hash(&self.original.expected_host_registration)
                    .as_bytes(),
                private_launch_digest: *blake3::hash(
                    self.original.private_launch.as_str().as_bytes(),
                )
                .as_bytes(),
                private_bootstrap: rows.private_bootstrap,
                native_birth: rows.native_birth,
                restore_prepare: rows.restore_prepare,
            },
            &self.original.key,
        )
        .map_err(|_| refused("native startup prefix data refused"))?;
        let length = u32::try_from(encoded_launch.len())
            .map_err(|_| refused("native startup launch length"))?;
        let extent = encoded_launch
            .len()
            .checked_add(4)
            .ok_or_else(|| refused("native startup launch overflow"))?;
        wire.launch
            .try_reserve_exact(extent)
            .map_err(|_| refused("native startup launch bank unavailable"))?;
        if wire.launch.capacity() > extent {
            return Err(refused("native startup launch capacity widened"));
        }
        wire.launch.extend_from_slice(&length.to_be_bytes());
        wire.launch.extend_from_slice(encoded_launch);
        self.prepare_private_boot_frame_into(&mut wire.boot)?;
        wire.boot
            .as_ref()
            .ok_or_else(|| refused("native startup boot frame absent"))?
            .retained_requested_storage_precredit_data(512 * 1024 + 4)
            .map_err(|_| refused("native startup boot capacity widened"))?;
        self.authenticate_original()?;
        wire.prepared = true;
        Ok(())
    }
}

impl PacketCompleteAckPeerBootMaterial<'_> {
    /// Retains this member's selected launch custody before terminal checks.
    ///
    /// All fallible phase, full-reference and quote guards run while the caller
    /// still owns its slot. The trusted slot identity callback precedes the
    /// complete reservation's installation. After installation, every refusal
    /// leaves the same original reservation in `completed`.
    ///
    /// # Errors
    /// Refuses a foreign/spent Source member, changed executable, populated
    /// native owner, unavailable slot, or actual requests above its admission.
    ///
    /// # Panics
    /// Propagates the trusted non-unwinding slot identity callback contract.
    pub fn reserve_original_native_startup_launch_into(
        &self,
        directory: &std::path::Path,
        executable: &crucible_node_contract::ContentRef,
        slot: &mut Option<Box<dyn crate::node_adapters::cnp::CnpSemanticProcessSlot>>,
        completed: &mut Option<crate::node_adapters::cnp::CnpSemanticLaunchReservation>,
    ) -> Result<(), OperationFailure> {
        use crate::node_adapters::cnp::CnpSemanticLaunchReservation;
        self.authenticate_startup_member()?;
        self.original.ensure_origin()?;
        if completed.is_some() {
            return Err(refused("native startup reservation slot occupied"));
        }
        let finalization = self
            .original
            .native_startup
            .as_ref()
            .ok_or_else(|| refused("native startup member unavailable"))?;
        if !finalization.complete {
            return Err(refused("native startup member incomplete"));
        }
        let maximum = finalization.member.host_launch_requested_bytes;
        let mut artifacts = self
            .source
            .installation()
            .provider
            .implementation
            .artifacts
            .iter()
            .filter(|artifact| artifact.role.as_str() == "executable");
        if artifacts
            .next()
            .is_none_or(|artifact| artifact.content != *executable)
            || artifacts.next().is_some()
        {
            return Err(refused(
                "native startup executable differs from original Source",
            ));
        }
        let unbound = match &self.source.original {
            super::super::super::CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound()?
            }
            super::super::super::CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound()?
            }
        };
        if !unbound
            || self
                .source
                .preconstruction
                .try_borrow()
                .map_err(|_| refused("native startup preconstruction busy"))?
                .is_some()
        {
            return Err(refused("native startup already associated"));
        }
        {
            let association = self
                .source
                .ack_peer_association
                .try_borrow()
                .map_err(|_| refused("native startup association already borrowed"))?;
            association
                .as_ref()
                .ok_or_else(|| refused("native startup reserved association absent"))?
                .authenticate_reserved_prebirth_data()?;
        }
        let slot_ref = slot
            .as_ref()
            .ok_or_else(|| refused("native startup original slot absent"))?;
        let future =
            CnpSemanticLaunchReservation::quote_unlaunched_retained_storage_precredit_data(
                directory,
                executable,
                slot_ref.as_ref(),
                maximum,
            )
            .map_err(|_| refused("native startup reservation quote refused"))?;
        let (retained, transient, scratch) =
            CnpSemanticLaunchReservation::quote_original_native_startup_acquisition_storage_data(
                executable, maximum,
            )
            .map_err(|_| refused("native startup acquisition quote refused"))?;
        future
            .checked_add(retained)
            .and_then(|bytes| bytes.checked_add(transient))
            .and_then(|bytes| bytes.checked_add(scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(|| refused("native startup host admission exceeded"))?;
        self.authenticate_original()?;
        if self.source.complete_bytes_launch_reserved.replace(true) {
            return Err(refused("native startup Source launch already spent"));
        }
        let original_slot = slot
            .take()
            .ok_or_else(|| refused("native startup original slot disappeared"))?;
        *completed = Some(
            CnpSemanticLaunchReservation::reserve_original_native_startup(
                directory.to_path_buf(),
                executable.clone(),
                original_slot,
            ),
        );
        self.original
            .bind_original_host_sdk_launch_data(
                completed
                    .as_ref()
                    .ok_or_else(|| refused("native startup custody absent"))?,
            )
            .map_err(|_| refused("original host SDK launch identity refused"))?;
        let actual = completed
            .as_ref()
            .ok_or_else(|| refused("native startup custody absent"))?
            .unlaunched_retained_requested_storage_precredit_data(maximum)
            .and_then(|report| report.complete_requested_bytes_precredit_data())
            .map_err(|_| refused("native startup custody observation refused"))?;
        if actual > future {
            return Err(refused("native startup custody capacity widened"));
        }
        self.authenticate_original()
    }

    // The import18 caller obtains its maximum only from its genuine installed
    // member. This private allocation path creates no member or credit.
    fn reserve_native_launch_with_original_member_data(
        &self,
        directory: &std::path::Path,
        executable: &crucible_node_contract::ContentRef,
        slot: &mut Option<Box<dyn crate::node_adapters::cnp::CnpSemanticProcessSlot>>,
        completed: &mut Option<crate::node_adapters::cnp::CnpSemanticLaunchReservation>,
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        use crate::node_adapters::cnp::CnpSemanticLaunchReservation;
        self.authenticate_startup_member()?;
        self.original.ensure_origin()?;
        if completed.is_some() {
            return Err(refused("native startup reservation slot occupied"));
        }
        let mut artifacts = self
            .source
            .installation()
            .provider
            .implementation
            .artifacts
            .iter()
            .filter(|artifact| artifact.role.as_str() == "executable");
        if artifacts
            .next()
            .is_none_or(|artifact| artifact.content != *executable)
            || artifacts.next().is_some()
        {
            return Err(refused(
                "native startup executable differs from original Source",
            ));
        }
        let unbound = match &self.source.original {
            super::super::super::CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound()?
            }
            super::super::super::CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound()?
            }
        };
        if !unbound
            || self
                .source
                .preconstruction
                .try_borrow()
                .map_err(|_| refused("native startup preconstruction busy"))?
                .is_some()
        {
            return Err(refused("native startup already associated"));
        }
        {
            let association = self
                .source
                .ack_peer_association
                .try_borrow()
                .map_err(|_| refused("native startup association already borrowed"))?;
            association
                .as_ref()
                .ok_or_else(|| refused("native startup reserved association absent"))?
                .authenticate_reserved_prebirth_data()?;
        }
        let slot_ref = slot
            .as_ref()
            .ok_or_else(|| refused("native startup original slot absent"))?;
        let future =
            CnpSemanticLaunchReservation::quote_unlaunched_retained_storage_precredit_data(
                directory,
                executable,
                slot_ref.as_ref(),
                maximum,
            )
            .map_err(|_| refused("native startup reservation quote refused"))?;
        let (retained, transient, scratch) =
            CnpSemanticLaunchReservation::quote_original_native_startup_acquisition_storage_data(
                executable, maximum,
            )
            .map_err(|_| refused("native startup acquisition quote refused"))?;
        future
            .checked_add(retained)
            .and_then(|bytes| bytes.checked_add(transient))
            .and_then(|bytes| bytes.checked_add(scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(|| refused("native startup host admission exceeded"))?;
        self.authenticate_original()?;
        if self.source.complete_bytes_launch_reserved.replace(true) {
            return Err(refused("native startup Source launch already spent"));
        }
        let original_slot = slot
            .take()
            .ok_or_else(|| refused("native startup original slot disappeared"))?;
        *completed = Some(
            CnpSemanticLaunchReservation::reserve_original_native_startup(
                directory.to_path_buf(),
                executable.clone(),
                original_slot,
            ),
        );
        self.original
            .bind_original_host_sdk_launch_data(
                completed
                    .as_ref()
                    .ok_or_else(|| refused("native startup custody absent"))?,
            )
            .map_err(|_| refused("original host SDK launch identity refused"))?;
        let actual = completed
            .as_ref()
            .ok_or_else(|| refused("native startup custody absent"))?
            .unlaunched_retained_requested_storage_precredit_data(maximum)
            .and_then(|report| report.complete_requested_bytes_precredit_data())
            .map_err(|_| refused("native startup custody observation refused"))?;
        if actual > future {
            return Err(refused("native startup custody capacity widened"));
        }
        self.authenticate_original()
    }
}

#[path = "native_wire/invocation.rs"]
mod invocation;

pub(super) use invocation::counter_scratch_data as original_native_invocation_wire_counter_scratch_data;

#[path = "native_wire/restored_suffix.rs"]
mod restored_suffix;

pub use restored_suffix::PacketCompleteNativeRestoredSuffixStartupWire;
pub(super) use restored_suffix::counter_scratch_data as original_restored_suffix_wire_counter_scratch_data;

#[path = "native_wire/restored_settled.rs"]
mod restored_settled;

pub use restored_settled::PacketCompleteNativeRestoredSettledStartupWire;
pub(super) use restored_settled::counter_scratch_data as original_restored_settled_wire_counter_scratch_data;
