//! Produces a bounded second private bootstrap frame from an original birth loan.
//!
//! The Native5 launcher retains this frame, its exact offset and the same original
//! socket writer/deadline until completion or supervised reclamation. The ordinary
//! one-frame Source2/4 launch path remains unchanged. Boot completion grants only
//! preparation; the post-Hello assigned Admit proof independently selects the
//! native canonical ACK mechanism.

use std::io::Write;

use crucible_node_format::{Bytes, canonical};

use super::{OperationFailure, PacketCompleteAckPeerBootMaterial, refused};

/// Bounds the complete source-generated canonical birth binding object.
pub const MAXIMUM_ACK_SOURCE_BIRTH_BYTES: usize = 384 * 1024;

/// Bounds the complete planned host registration object before Hello.
pub const MAXIMUM_ACK_HOST_REGISTRATION_BYTES: usize = 16 * 1024;

/// Bounds the second private bootstrap body independently of the first launch.
pub const MAXIMUM_ACK_PRIVATE_BOOT_BYTES: usize = 512 * 1024;

/// Retains an independently allocated private frame and its actual write progress.
///
/// This object has no public constructor or serialization implementation. Its
/// bytes include the private transport key and must not be logged. A refused
/// write retains the full original frame and its literal cursor. Its launcher
/// must retain the same original socket writer alongside it; this data object
/// cannot substitute another socket, deadline or child association.
pub struct PacketCompleteAckPeerBootFrame {
    process: u32,
    thread: std::thread::ThreadId,
    frame: Vec<u8>,
    prepared: bool,
    birth_id: [u8; 32],
    written: usize,
}

impl PacketCompleteAckPeerBootFrame {
    /// Reports this distinct actual encoded reservation capacity.
    ///
    /// # Errors
    /// Refuses a foreign creator process or thread before reading the bank.
    pub fn allocated_capacity(&self) -> Result<usize, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.frame.capacity())
    }

    /// Observes this actual encoded bank without a currentness callback.
    ///
    /// The owner inline layout is counted by its containing launch holder.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or a capacity above the caller window.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if self.frame.capacity() > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(self.frame.capacity())
    }

    /// Reports the actual literal offset without claiming remote completion.
    ///
    /// # Errors
    /// Refuses a foreign creator process or thread before reading progress.
    pub fn written_bytes(&self) -> Result<usize, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.written)
    }

    fn ensure_origin(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() {
            return Err(refused("private ACK frame belongs to another process"));
        }
        if self.thread != std::thread::current().id() {
            return Err(refused("private ACK frame belongs to another thread"));
        }
        Ok(())
    }

    /// Writes the retained frame through the launcher's same original writer.
    ///
    /// The caller keeps its original writer and deadline outside every unwind
    /// boundary. Each successful short write advances this exact cursor. A
    /// failure neither clears bytes nor recreates a frame or startup deadline.
    ///
    /// # Errors
    /// Refuses a foreign creator, incomplete preparation, a zero-length write
    /// or an original writer failure; all original progress remains retained.
    pub fn write_original(
        &mut self,
        material: &PacketCompleteAckPeerBootMaterial<'_>,
        writer: &mut impl Write,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        material.authenticate_original()?;
        if material.birth_id()? != &self.birth_id {
            return Err(refused(
                "private ACK frame belongs to another original birth",
            ));
        }
        if !self.prepared {
            return Err(refused("private ACK original frame is not prepared"));
        }
        while self.written < self.frame.len() {
            self.ensure_origin()?;
            material.authenticate_original()?;
            match writer.write(&self.frame[self.written..]) {
                Ok(0) => return Err(refused("private ACK original writer made no progress")),
                Ok(length) if length <= self.frame.len() - self.written => self.written += length,
                Ok(_) => return Err(refused("private ACK original writer extent changed")),
                Err(_) => return Err(refused("private ACK original writer refused")),
            }
        }
        material.authenticate_original()?;
        self.ensure_origin()
    }
}

impl PacketCompleteAckPeerBootMaterial<'_> {
    /// Prepares the bounded second frame in a caller-retained original slot.
    ///
    /// The launcher invokes this before Child, after reserving and accounting
    /// the source birth and planned registration banks. This method fills the
    /// frame slot before parsing or encoding its secret body. A refused or
    /// unwound preparation retains the same allocation and partial bytes and
    /// cannot restart with another context.
    ///
    /// # Errors
    /// Refuses changed source origin/executable, an occupied result slot,
    /// unavailable reservation or actual nested/encoded data beyond selection.
    pub fn prepare_private_boot_frame_into(
        &self,
        completed: &mut Option<PacketCompleteAckPeerBootFrame>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original()?;
        if completed.is_some() {
            return Err(refused("private ACK original frame slot is occupied"));
        }
        let source_birth = self.source_birth_bytes()?;
        let host_registration = self.expected_host_registration_bytes()?;
        if source_birth.len() > MAXIMUM_ACK_SOURCE_BIRTH_BYTES
            || host_registration.len() > MAXIMUM_ACK_HOST_REGISTRATION_BYTES
        {
            return Err(refused(
                "private ACK complete birth inputs exceed selection",
            ));
        }

        let mut frame = Vec::new();
        frame
            .try_reserve_exact(MAXIMUM_ACK_PRIVATE_BOOT_BYTES + 4)
            .map_err(|_| refused("private ACK encoded reservation unavailable"))?;
        frame.extend_from_slice(&[0; 4]);
        *completed = Some(PacketCompleteAckPeerBootFrame {
            process: std::process::id(),
            thread: std::thread::current().id(),
            frame,
            prepared: false,
            birth_id: *self.birth_id()?,
            written: 0,
        });
        let original = completed
            .as_mut()
            .ok_or_else(|| refused("private ACK reserved frame slot absent"))?;

        // Both parsed trees and the final encoded buffer are distinct source
        // scratch/backing. The full capture peak must account them separately.
        let body = serde_json::json!({
            "schema": self.original_private_boot_schema_data()?,
            "private_key": Bytes::new(self.private_key()?.to_vec()),
            "birth_id": Bytes::new(self.birth_id()?.to_vec()),
            "source_birth": canonical::parse_json(source_birth, MAXIMUM_ACK_SOURCE_BIRTH_BYTES)
                .map_err(|_| refused("private ACK birth object is invalid"))?,
            "expected_host_registration": canonical::parse_json(
                host_registration, MAXIMUM_ACK_HOST_REGISTRATION_BYTES,
            ).map_err(|_| refused("private ACK registration object is invalid"))?,
            "private_launch": self.private_launch()?,
            "host_executable": self.host_executable()?,
        });
        canonical::canonical_json_to_writer(
            &body,
            &mut ReservedFrameWriter {
                frame: &mut original.frame,
            },
        )
        .map_err(|_| refused("private ACK canonical frame exceeds selection"))?;
        let length = u32::try_from(original.frame.len() - 4)
            .map_err(|_| refused("private ACK original length overflow"))?;
        original.frame[..4].copy_from_slice(&length.to_be_bytes());
        self.authenticate_original()?;
        original.prepared = true;
        Ok(())
    }
}

struct ReservedFrameWriter<'a> {
    frame: &'a mut Vec<u8>,
}

impl Write for ReservedFrameWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end =
            self.frame.len().checked_add(bytes.len()).ok_or_else(|| {
                std::io::Error::other("private ACK original frame extent overflow")
            })?;
        if end > MAXIMUM_ACK_PRIVATE_BOOT_BYTES + 4 || end > self.frame.capacity() {
            return Err(std::io::Error::other(
                "private ACK original frame reservation exceeded",
            ));
        }
        self.frame.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
