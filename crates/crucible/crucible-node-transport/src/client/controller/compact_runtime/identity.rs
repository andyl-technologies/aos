//! Reads the retained original registrar, peer and descriptor through runtime custody.
//!
//! These narrow views preserve the same original Session and actor. They expose
//! neither a mutable legacy controller nor a replacement control connection.

use super::*;
use crate::client::CnpRegistrarRead;
use crate::handshake::{ExtensionHandshake, Handshake};

impl CompactRuntimeController {
    /// Reports the peer PID saved by the same original authenticated Session.
    ///
    /// This diagnostic value alone supplies no current kernel identity proof.
    pub fn peer_pid(&self) -> u32 {
        self.original.peer_pid()
    }

    /// Borrows the executable reference retained by the original Session.
    ///
    /// The Source independently checks the actual process and measured bytes.
    pub fn peer_executable(&self) -> &ContentRef {
        self.original.peer_executable()
    }

    /// Issues the same original registrar read under its surviving handshake.
    ///
    /// No registration, deadline or quota is replaced. Native process identity
    /// and Source permission remain independent requirements.
    ///
    /// # Errors
    /// Refuses a foreign creator, fenced owner, revoked registrar or handshake
    /// from a different original connection.
    pub fn original_registrar_read(
        &self,
        handshake: &Handshake,
    ) -> Result<CnpRegistrarRead, ProviderError> {
        self.original.protocol_owner.ensure_current()?;
        self.original.original_registrar_read(handshake)
    }

    /// Issues the same original registrar read under its typed handshake.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, fenced owner, revoked registration or
    /// typed handshake from a different original connection.
    pub fn original_registrar_read_extensions(
        &self,
        handshake: &ExtensionHandshake,
    ) -> Result<CnpRegistrarRead, ProviderError> {
        self.original.original_registrar_read_extensions(handshake)
    }

    /// Counts the actual retained control descriptor without requiring live effects.
    ///
    /// Fencing and registrar revocation preserve the owned stream descriptor.
    /// The caller independently counts supervisor, native and kernel resources.
    ///
    /// # Errors
    /// Refuses a foreign creator or unsupported retained stream ownership.
    pub fn retained_descriptor_count_data(&self) -> Result<usize, ProviderError> {
        self.original.retained_descriptor_count_data()
    }
}
