//! Borrows actual current-occurrence Capture proof slots without future receipts.

use super::*;
use crate::{
    bodies::{BeginRequest, CaptureArguments},
    envelope::Envelope,
    reference_packet::service::{
        restored_settled_capture::{
            PacketRestoredSettledCaptureArtifact, PacketRestoredSettledCaptureContext,
        },
        restored_settled_confirmation::PacketRestoredSettledAfterConfirmationRequest,
    },
};

impl NativeCurrentGraph17Data {
    /// Borrows the selected occurrence's actual signed Capture artifact.
    ///
    /// # Errors
    /// Refuses an incomplete graph or an occurrence without a Capture artifact.
    pub(crate) fn current_capture_artifact17_data(
        &self,
    ) -> Result<&PacketRestoredSettledCaptureArtifact, ProviderError> {
        self.validate_data()?;
        Ok(&self
            .lineage
            .capture_data()
            .capture
            .value_data()?
            .as_ref()
            .ok_or_else(invalid)?
            .0)
    }

    /// Borrows the actual corresponding native Capture signing context.
    ///
    /// # Errors
    /// Refuses an incomplete graph or absent actual Capture context.
    pub(crate) fn current_capture_context17_data(
        &self,
    ) -> Result<&PacketRestoredSettledCaptureContext, ProviderError> {
        self.validate_data()?;
        Ok(&self
            .lineage
            .capture_data()
            .capture_context
            .value_data()?
            .as_ref()
            .ok_or_else(invalid)?
            .0)
    }

    /// Borrows the selected occurrence's actual current request, including Poll.
    ///
    /// # Errors
    /// Refuses an incomplete graph, absent current action or absent original.
    pub(crate) fn current_action_original17_data(&self) -> Result<&Envelope, ProviderError> {
        self.validate_data()?;
        self.lineage.current_action.as_ref().ok_or_else(invalid)?;
        self.lineage
            .capture_data()
            .original
            .value_data()?
            .as_ref()
            .ok_or_else(invalid)
    }

    /// Returns the actual registration identity group from the same Boot source walk.
    ///
    /// # Errors
    /// Refuses an incomplete graph or absent actual registration identity.
    pub(crate) fn current_capture_registration_identity_group17_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.validate_data()?;
        self.lineage
            .current_capture_registration_identity_group17_data()
    }

    /// Borrows the actual registration request and its independent typed caches.
    ///
    /// # Errors
    /// Refuses an incomplete graph or an occurrence without completed registration.
    pub(crate) fn current_capture_registration17_data(
        &self,
    ) -> Result<(&Envelope, &CaptureArguments, &BeginRequest), ProviderError> {
        self.validate_data()?;
        let registration = self.lineage.registration_data();
        Ok((
            registration.request.value_data()?,
            &registration.arguments.value_data()?.0,
            &registration.begin.value_data()?.0,
        ))
    }

    /// Borrows the current actual confirmation request without requiring its future reply.
    ///
    /// # Errors
    /// Refuses incomplete data or an occurrence without a confirmation request.
    pub(crate) fn current_capture_confirmation17_data(
        &self,
    ) -> Result<&PacketRestoredSettledAfterConfirmationRequest, ProviderError> {
        self.validate_data()?;
        Ok(&self
            .lineage
            .capture_data()
            .confirmation
            .value_data()?
            .as_ref()
            .ok_or_else(invalid)?
            .0)
    }
}
