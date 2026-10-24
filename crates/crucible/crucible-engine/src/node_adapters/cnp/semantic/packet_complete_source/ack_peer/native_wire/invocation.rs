//! Retains the exact source-issued invocation15 wire and partial write progress.
//!
//! The unchanged bank owner holds prefix15, launch6 and boot7. The source-bound
//! purpose is read only from its real complete Core member's retained Source15;
//! no caller purpose field or general raw-byte constructor is accepted.

use super::*;
use crucible_node_transport::reference_packet::service::native_startup::{
    PacketNativeInvocationPreambleData, encode_original_native_invocation_preamble_data,
    original_native_invocation_launch_identity_data, write_original_native_invocation_launch_data,
};

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
    /// Identifies a completed real invocation-bound Source, without selecting purpose.
    ///
    /// This is data routing only. The distinct writer still authenticates the
    /// actual private member, full target and immutable encoded launch bank.
    ///
    /// # Errors
    /// Refuses incomplete, foreign or revoked original Source/member custody.
    pub fn requires_original_native_invocation_wire_data(&self) -> Result<bool, OperationFailure> {
        self.authenticate_original()?;
        self.original
            .native_startup
            .as_ref()
            .ok_or_else(|| refused("native startup owner absent"))?
            .original_invocation_data()
            .map(|data| data.is_some())
            .map_err(|_| refused("native invocation Source binding"))
    }

    /// Retains prefix15, original launch6 and private boot7 before any Child.
    ///
    /// The same source-bound purpose and typed launch are requoted by Core before
    /// this entry. Every bank and partial encoding remains in `completed` if a
    /// later allocation, encoding or final currentness check refuses.
    ///
    /// # Errors
    /// Refuses occupied output, another actual launch/target, missing genuine
    /// member, changed wrapper identity, exhausted fixed capacity or currency.
    pub fn prepare_original_native_invocation_wire_into(
        &self,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        completed: &mut Option<PacketCompleteNativeStartupWire>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original()?;
        if completed.is_some() {
            return Err(refused("native invocation wire slot occupied"));
        }
        self.source
            .authenticate_native_launch_data(launch)
            .map_err(|_| refused("native invocation launch differs"))?;
        let state = self
            .original
            .native_startup
            .as_ref()
            .ok_or_else(|| refused("native invocation member absent"))?;
        if state.member.suffix.is_some() {
            return Err(refused(
                "restored suffix requires its distinct original wire entry",
            ));
        }
        if !state.complete {
            return Err(refused("native invocation Source incomplete"));
        }
        let purpose = state
            .original_invocation_data()
            .map_err(|_| refused("native invocation Source binding"))?
            .ok_or_else(|| refused("native invocation Source edition absent"))?;
        purpose
            .authenticate_target_data(launch)
            .map_err(|_| refused("native invocation target differs"))?;
        let identity = original_native_invocation_launch_identity_data(&purpose, canonical_launch5)
            .map_err(|_| refused("native invocation launch identity"))?;
        if identity.raw_digest != state.member.launch_digest || identity.encoded_bytes > 1024 * 1024
        {
            return Err(refused("native invocation original launch differs"));
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
            .ok_or_else(|| refused("native invocation wire absent"))?;
        let rows = state.member.rows;
        wire.preamble = encode_original_native_invocation_preamble_data(
            &PacketNativeInvocationPreambleData {
                controller_pid: launch.controller_pid.get(),
                controller_uid: launch.controller_uid.get(),
                launch_bytes: u32::try_from(identity.encoded_bytes)
                    .map_err(|_| refused("native invocation launch extent"))?,
                maximum_boot_bytes: u32::try_from(state.member.maximum_boot_bytes)
                    .map_err(|_| refused("native invocation boot extent"))?,
                birth_id: self.original.birth_id,
                launch_digest: state.member.launch_digest,
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
        .map_err(|_| refused("native invocation prefix DATA"))?;
        let maximum = identity
            .encoded_bytes
            .checked_add(4)
            .ok_or_else(|| refused("native invocation wire extent"))?;
        wire.launch
            .try_reserve_exact(maximum)
            .map_err(|_| refused("native invocation bank unavailable"))?;
        if wire.launch.capacity() > maximum {
            return Err(refused("native invocation bank capacity widened"));
        }
        let length = u32::try_from(identity.encoded_bytes)
            .map_err(|_| refused("native invocation body extent"))?;
        wire.launch.extend_from_slice(&length.to_be_bytes());
        write_original_native_invocation_launch_data(
            &purpose,
            canonical_launch5,
            &mut Limited {
                bank: &mut wire.launch,
                maximum,
            },
        )
        .map_err(|_| refused("native invocation retained encoding refused"))?;
        if wire.launch.len() != maximum
            || blake3::hash(&wire.launch[4..]).as_bytes() != &state.member.launch_digest
        {
            return Err(refused("native invocation constructed bank differs"));
        }
        self.prepare_private_boot_frame_into(&mut wire.boot)?;
        self.authenticate_original()?;
        wire.prepared = true;
        Ok(())
    }
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) const fn counter_scratch_data()
-> usize {
    std::mem::size_of::<Limited<'static>>()
        + std::mem::size_of::<PacketNativeInvocationPreambleData>()
        + std::mem::size_of::<crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationLaunchIdentityData>()
        + std::mem::size_of::<[u8; 4]>() + 4 * std::mem::size_of::<usize>()
}
