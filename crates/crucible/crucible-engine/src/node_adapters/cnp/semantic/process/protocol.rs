//! Borrows the one actual SDK owner without exposing mutable legacy custody.
//!
//! Both alternatives retain their same registrar, control peer and descriptor.
//! This view supplies ownership facts only. It cannot construct a runtime owner,
//! authorize the Source handoff or lend an old controller through the runtime.

use super::*;
use crucible_node_transport::{client::CnpRegistrarRead, handshake::ConnectionAuthority};

/// Borrows one exclusive protocol owner without granting control effects.
pub(super) enum OriginalControllerView<'a> {
    /// Borrows the original controller before its runtime move.
    Legacy(&'a CnpController),
    /// Borrows the opaque runtime owner, including its retained legacy prefix.
    Compact(&'a CompactRuntimeController),
}

impl CnpSemanticProcessCustody {
    /// Borrows the selected original SDK after checking custody origin.
    ///
    /// # Errors
    /// Refuses a foreign creator or two competing controller owners.
    pub(super) fn original_controller_data(
        &self,
    ) -> Result<Option<OriginalControllerView<'_>>, ProviderError> {
        self.ensure_origin()?;
        match (&self.controller, &self.compact_runtime) {
            (Some(controller), None) => Ok(Some(OriginalControllerView::Legacy(controller))),
            (None, Some(controller)) => Ok(Some(OriginalControllerView::Compact(controller))),
            (None, None) => Ok(None),
            (Some(_), Some(_)) => Err(ProviderError::Correlation(
                "generic original control custody is ambiguous",
            )),
        }
    }
}

impl OriginalControllerView<'_> {
    /// Borrows the same original registration authority.
    pub(super) fn authority(&self) -> &ConnectionAuthority {
        match self {
            Self::Legacy(controller) => controller.authority(),
            Self::Compact(controller) => controller.authority(),
        }
    }

    /// Reports the original Session's saved peer PID as data.
    pub(super) fn peer_pid(&self) -> u32 {
        match self {
            Self::Legacy(controller) => controller.peer_pid(),
            Self::Compact(controller) => controller.peer_pid(),
        }
    }

    /// Borrows the original Session's saved executable reference as data.
    pub(super) fn peer_executable(&self) -> &ContentRef {
        match self {
            Self::Legacy(controller) => controller.peer_executable(),
            Self::Compact(controller) => controller.peer_executable(),
        }
    }

    /// Reads the same original registrar under its surviving handshake.
    ///
    /// # Errors
    /// Refuses fenced, revoked or mismatched original registration.
    pub(super) fn original_registrar_read(
        &self,
        handshake: &Handshake,
    ) -> Result<CnpRegistrarRead, ProviderError> {
        match self {
            Self::Legacy(controller) => controller.original_registrar_read(handshake),
            Self::Compact(controller) => controller.original_registrar_read(handshake),
        }
    }

    /// Reads the same original registrar under its surviving typed handshake.
    ///
    /// # Errors
    /// Refuses foreign, fenced, revoked or mismatched original custody.
    pub(super) fn original_registrar_read_extensions(
        &self,
        handshake: &ExtensionHandshake,
    ) -> Result<CnpRegistrarRead, ProviderError> {
        match self {
            Self::Legacy(controller) => controller.original_registrar_read_extensions(handshake),
            Self::Compact(controller) => controller.original_registrar_read_extensions(handshake),
        }
    }

    /// Counts the same owned descriptor independently of live effects.
    ///
    /// # Errors
    /// Refuses foreign or unsupported actual stream ownership.
    pub(super) fn retained_descriptor_count_data(&self) -> Result<usize, ProviderError> {
        match self {
            Self::Legacy(controller) => controller.retained_descriptor_count_data(),
            Self::Compact(controller) => controller.retained_descriptor_count_data(),
        }
    }
}
