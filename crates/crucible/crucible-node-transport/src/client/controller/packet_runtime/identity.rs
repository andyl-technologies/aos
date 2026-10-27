//! Borrows the unchanged original registrar, peer and retained descriptor DATA.

use super::*;
use crate::handshake::{ExtensionHandshake, Handshake};

impl PacketRuntimeController {
    /// Reports the peer PID retained by the same original authenticated session.
    ///
    /// This diagnostic alone authenticates no current kernel process identity.
    pub fn peer_pid(&self) -> u32 {
        self.runtime.peer_pid()
    }

    /// Borrows the executable reference retained by the same original session.
    pub fn peer_executable(&self) -> &ContentRef {
        self.runtime.peer_executable()
    }

    /// Borrows the original registrar under its surviving handshake.
    ///
    /// # Errors
    /// Refuses a foreign creator, fenced owner, revoked registrar or a handshake
    /// belonging to another original connection.
    pub fn original_registrar_read(
        &self,
        handshake: &Handshake,
    ) -> Result<CnpRegistrarRead, ProviderError> {
        self.runtime.original_registrar_read(handshake)
    }

    /// Borrows the original registrar under its typed extension handshake.
    ///
    /// # Errors
    /// Refuses foreign creators, fenced ownership, revoked registration or a
    /// typed handshake belonging to another original connection.
    pub fn original_registrar_read_extensions(
        &self,
        handshake: &ExtensionHandshake,
    ) -> Result<CnpRegistrarRead, ProviderError> {
        self.runtime.original_registrar_read_extensions(handshake)
    }

    /// Counts the same retained control descriptor after fencing or revocation.
    ///
    /// Supervisor, native and kernel resources remain independent owners.
    ///
    /// # Errors
    /// Refuses a foreign creator or unsupported retained stream ownership.
    pub fn retained_descriptor_count_data(&self) -> Result<usize, ProviderError> {
        self.runtime.retained_descriptor_count_data()
    }
}
