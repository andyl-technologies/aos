//! Counts and attaches the same selected host control owners under a Source action.
//!
//! The SDK retains custody; the concrete Core-private sink owns the installed
//! action. Neither this trait nor numeric data supplies permission to issue
//! Discover, Realize, keyed Admit or any later control operation.

use super::*;
use crate::handshake::ConnectionAuthority;

mod storage;
pub use storage::{
    PacketNativeHostInitialLifecycleStorageData,
    original_packet_host_initial_lifecycle_counter_scratch_data,
};

/// Borrows actual selected attachment data without exposing a controller.
pub struct OriginalPacketHostInitialAttachmentScope<'a> {
    startup: &'a OriginalPacketHostStartup,
}

impl OriginalPacketHostInitialAttachmentScope<'_> {
    /// Borrows the same immutable installed codec selection.
    ///
    /// # Errors
    /// Refuses a foreign creator or absent original controller.
    pub fn selection_data(&self) -> Result<&PacketControlSelection, ProviderError> {
        self.startup.creator.ensure_current()?;
        self.startup.selection.as_ref().ok_or_else(refused)
    }

    /// Borrows the actual live negotiated registration.
    ///
    /// # Errors
    /// Refuses a foreign creator or absent original controller.
    pub fn authority_data(&self) -> Result<&ConnectionAuthority, ProviderError> {
        self.startup.creator.ensure_current()?;
        let controller = self.startup.controller.as_ref().ok_or_else(refused)?;
        controller.authority().ensure_live()?;
        Ok(controller.authority())
    }

    /// Returns the kernel-associated PID already verified by the selected Hello.
    ///
    /// # Errors
    /// Refuses a foreign creator or absent original controller.
    pub fn peer_pid_data(&self) -> Result<u32, ProviderError> {
        self.startup.creator.ensure_current()?;
        Ok(self
            .startup
            .controller
            .as_ref()
            .ok_or_else(refused)?
            .peer_pid())
    }

    /// Borrows the independently measured executable retained by that Hello.
    ///
    /// # Errors
    /// Refuses a foreign creator or absent original controller.
    pub fn peer_executable_data(&self) -> Result<&ContentRef, ProviderError> {
        self.startup.creator.ensure_current()?;
        Ok(self
            .startup
            .controller
            .as_ref()
            .ok_or_else(refused)?
            .peer_executable())
    }
}

/// Receives one selected attachment directly into its original guarded capsule.
///
/// A Core-private implementation retains and consumes its genuine installed
/// Source action. Implementing this public custody interface supplies no such
/// authority. Implementations validate the actual Source/guard/member/currency
/// before taking anything, preserve every owning slot on refusal/unwind, and
/// move directly through the existing guarded attachment operation. They must
/// retain the original Hello in the same registered owner before returning.
pub trait OriginalPacketHostInitialAttachmentSink {
    /// Authenticates actual Source and native custody before any owner moves.
    ///
    /// # Errors
    /// Refuses missing, spent, foreign or changed action/guard associations.
    fn authenticate_original_attachment_data(
        &mut self,
        scope: &OriginalPacketHostInitialAttachmentScope<'_>,
    ) -> Result<(), ProviderError>;

    /// Transfers the original controller, typed registrar and literal Hello slots.
    ///
    /// # Errors
    /// Leaves owners retained in the original input or guarded output slots on
    /// any refusal. A returned error must never drop or replace those owners.
    fn retain_original_attachment_into(
        &mut self,
        controller: &mut Option<CnpController>,
        handshake: &mut Option<ExtensionHandshake>,
        hello: &mut Option<OriginalHelloJournal>,
    ) -> Result<(), ProviderError>;
}

impl OriginalPacketHostStartup {
    /// Quotes the selected codec and three initial methods before Hello exists.
    ///
    /// The Source supplies its actual immutable typed launch and admits this
    /// counter before the call. The result grants no socket or control rights.
    ///
    /// # Errors
    /// Refuses foreign/partial/repeated roots, changed launch data, unsupported
    /// selected tuples or checked requested-storage overflow.
    pub fn quote_original_initial_lifecycle_storage_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<PacketNativeHostInitialLifecycleStorageData, ProviderError> {
        self.creator.ensure_current()?;
        if !self.prepared
            || self.preparing
            || self.connecting
            || self.failure.is_some()
            || self.initial_attachment_attempted
            || self.frames.is_none()
            || self.selection.as_ref() != Some(&launch.selection)
            || self.profile.as_ref() != Some(&launch.capture_profile)
            || self.coordinator.as_ref().is_none_or(|current| {
                current.reference != launch.initial_coordinator.reference
                    || current.bytes.as_slice() != launch.initial_coordinator.bytes.as_slice()
            })
        {
            return Err(refused());
        }
        self.registration
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_launch(launch)?;
        storage::quote(self, launch)
    }

    /// Installs the selected codec and moves only into an action-bearing sink.
    ///
    /// The same Data is recomputed after the real Hello before codec allocation.
    /// The sink validates actual Source/native custody before the one-shot flag,
    /// and again before directly attaching the original owning slots. No general
    /// controller getter or standalone controller result is exposed.
    ///
    /// # Errors
    /// Refuses incomplete/currently changed originals, insufficient admitted
    /// components, unsupported policy or changed sink. Partial owners remain in
    /// this startup or the concrete guarded sink; the attempt never renews.
    ///
    /// # Panics
    /// A trusted concrete sink may unwind. The one-shot flag is already spent;
    /// original input or guarded output slots continue to own the same values.
    pub fn attach_original_initial_lifecycle_into(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        admitted: &PacketNativeHostInitialLifecycleStorageData,
        supervisor: &OriginalRetainedSupervisor,
        sink: &mut impl OriginalPacketHostInitialAttachmentSink,
    ) -> Result<(), ProviderError> {
        self.creator.ensure_current()?;
        if !self.connected
            || self.controller.is_none()
            || self.handshake.is_none()
            || self.hello_journal.is_none()
        {
            return Err(refused());
        }
        self.reconcile_connected_data(supervisor)?;
        let current = self.quote_original_initial_lifecycle_storage_data(launch)?;
        if !current.within(admitted) {
            return Err(refused());
        }
        sink.authenticate_original_attachment_data(&OriginalPacketHostInitialAttachmentScope {
            startup: self,
        })?;
        self.initial_attachment_attempted = true;
        let result = (|| {
            let controller = self.controller.as_mut().ok_or_else(refused)?;
            controller
                .prepare_original_host_initial_capacity_data(admitted.journal_growth_data())?;
            let selection = self.selection.as_ref().ok_or_else(refused)?.clone();
            let coordinator = self.coordinator.as_ref().ok_or_else(refused)?.clone();
            let profile = self.profile.as_ref().ok_or_else(refused)?.clone();
            let extent = launch.native_codec_metadata_extent.ok_or_else(refused)?;
            if launch.fresh_restore_allocation_selection.is_some() {
                controller.install_native5_source_fresh_restore_allocation_codec_with_metadata_extent(&mut self.frames, selection, coordinator, profile, extent)?;
            } else if launch.restore_input_emitter_selection.is_some() {
                controller.install_native5_source_restore_input_emitter_codec_with_metadata_extent(&mut self.frames, selection, coordinator, profile, extent)?;
            } else if launch.complete_restore_selection == Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
                controller.install_native5_source_complete_restore_transfer_codec_with_metadata_extent(&mut self.frames, selection, coordinator, profile, extent)?;
            } else if launch.complete_restore_selection.is_some() {
                controller.install_native5_source_complete_restore_codec_with_metadata_extent(&mut self.frames, selection, coordinator, profile, extent)?;
            } else {
                controller.install_native5_source_ack_emitter_codec_with_metadata_extent(&mut self.frames, selection, coordinator, profile, extent)?;
            }
            let actual = self.retained_requested_storage_data(Some(supervisor))?;
            if actual
                > self
                    .quote
                    .retained_requested_bytes()
                    .checked_add(admitted.retained_growth_bytes())
                    .ok_or_else(refused)?
            {
                return Err(refused());
            }
            sink.authenticate_original_attachment_data(
                &OriginalPacketHostInitialAttachmentScope { startup: self },
            )?;
            sink.retain_original_attachment_into(
                &mut self.controller,
                &mut self.handshake,
                &mut self.hello_journal,
            )?;
            if self.controller.is_some() || self.handshake.is_some() || self.hello_journal.is_some()
            {
                return Err(refused());
            }
            self.creator.ensure_current()
        })();
        if let Err(error) = result {
            self.failure = Some(error);
            return Err(refused());
        }
        Ok(())
    }
}
