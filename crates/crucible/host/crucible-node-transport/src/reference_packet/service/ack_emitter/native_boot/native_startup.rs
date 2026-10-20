//! Retains the actual boot6 baseline action and its nonrenewing Prepare occurrence.
//!
//! Only the new original private-bootstrap path can construct this owner, after
//! associating its retained preamble and exact canonical launch/boot bodies.
//! Decoded allocation rows alone never construct a native scope.

use super::*;
use crate::reference_packet::service::native_startup::{
    PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA, PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA,
    PacketNativeStartupAllocation, PacketNativeStartupAllocationRow,
};

pub(in crate::reference_packet::service::ack_emitter::native_boot) struct OriginalNativeStartupBoot
{
    pub(in crate::reference_packet::service::ack_emitter::native_boot) restored_suffix:
        Option<Box<super::restored_suffix::NativeRestoredSuffixStartupOwner>>,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) allocation:
        PacketNativeStartupAllocation,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) source_digest: [u8; 32],
    pub(in crate::reference_packet::service::ack_emitter::native_boot) launch_digest: [u8; 32],
    pub(in crate::reference_packet::service::ack_emitter::native_boot) birth_id: [u8; 32],
    pub(in crate::reference_packet::service::ack_emitter::native_boot) native_birth_issued: bool,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) baseline_complete: bool,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) prepare_startup_issued: bool,
}

impl NativeAckBoot {
    fn authenticate_native_startup_data(
        &self,
    ) -> Result<&OriginalNativeStartupBoot, ProviderError> {
        self.ensure_origin()?;
        let original = self
            .startup
            .as_ref()
            .ok_or(ProviderError::Correlation("native startup origin absent"))?;
        if !self.ready
            || !self.verified
            || !original.native_birth_issued
            || !original.baseline_complete
            || self.data.schema != PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA
            || self
                .data
                .source_birth
                .get("schema")
                .and_then(serde_json::Value::as_str)
                != Some(PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)
            || self.data.birth_id.as_slice() != original.birth_id
            || blake3::hash(&self.launch_body).as_bytes() != &original.launch_digest
            || blake3::hash(&self.source_body).as_bytes() != &original.source_digest
        {
            return Err(ProviderError::Correlation(
                "native startup original body differs",
            ));
        }
        Ok(original)
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_original_native_baseline_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.authenticate_native_startup_data().map(|_| ())
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn original_native_prepare_startup_row_data(
        &self,
    ) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
        let original = if self.data.schema == crate::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            self.authenticate_original_invocation_prepare_target_data()?;
            self.startup.as_ref().ok_or(ProviderError::Correlation("native invocation origin absent"))?
        } else {
            self.authenticate_native_startup_data()?
        };
        original
            .allocation
            .restore_prepare
            .ok_or(ProviderError::Correlation(
                "native Prepare startup not selected",
            ))
    }

    // The verified token authenticates its actual connection/boot/policy before
    // borrowing this owner mutably. Once claimed, no read/error/unwind can reopen
    // the occurrence merely because no Prepare attempt has been installed yet.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn claim_original_native_prepare_startup_row_data(
        &mut self,
    ) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
        let row = self.original_native_prepare_startup_row_data()?;
        let original = self
            .startup
            .as_mut()
            .ok_or(ProviderError::Correlation("native startup origin absent"))?;
        if std::mem::replace(&mut original.prepare_startup_issued, true) {
            return Err(ProviderError::Conflict(
                "native Prepare startup already claimed",
            ));
        }
        Ok(row)
    }
}

#[path = "native_startup_receive.rs"]
mod receive;
pub(crate) use receive::OriginalNativeBirthReadScope;

impl NativeAckBoot {
    /// Borrows initial Hello credit from the same actual original boot6 owner.
    ///
    /// Decoded rows and ordinary service entries cannot create this owner.
    /// Other boot editions retain their existing receive path.
    ///
    /// # Errors
    /// Refuses creator drift, unavailable or completed original birth state.
    pub(crate) fn original_native_hello_preflight<'a>(
        &'a self,
        launch: &'a crate::reference_packet::service::PacketNative5SourceLaunch,
    ) -> Result<
        Option<crate::reference_packet::service::native_startup::OriginalNativeFramePreflight<'a>>,
        ProviderError,
    > {
        self.ensure_origin()?;
        let Some(original) = self.startup.as_ref() else {
            return Ok(None);
        };
        // Keep the separate invocation consumer's old admission path intact.
        if self.data.schema != PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA {
            return Ok(None);
        }
        if !self.ready
            || self.verified
            || !original.native_birth_issued
            || original.baseline_complete
        {
            return Err(ProviderError::Correlation(
                "native original Hello scope unavailable",
            ));
        }
        Ok(Some(
            crate::reference_packet::service::native_startup::OriginalNativeFramePreflight::hello(
                &original.allocation.native_birth,
                launch,
                &self.host_body,
            ),
        ))
    }
}
