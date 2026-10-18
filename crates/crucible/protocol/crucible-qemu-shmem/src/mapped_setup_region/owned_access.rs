//! Mutable wire operations tied to the ordinary mapping owner's lifetime.
//!
//! These delegates return only validated ring/transport borrows or perform
//! bounded image restoration. The whole non-owning view remains private, so
//! safe callers cannot replace the geometry retained by the physical owner.

use super::*;

impl MappedSetupRegion {
    /// Borrows one owned node slot and two distinct directed rings.
    ///
    /// Delegates to [`MappedSetupView::node_directed_ring_pair_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn node_directed_ring_pair_mut(
        &mut self,
        node_slot: u32,
        first_src_slot: u32,
        first_dst_slot: u32,
        second_src_slot: u32,
        second_dst_slot: u32,
    ) -> Result<MappedNodeRingPairMut<'_>, MappedSetupRegionAccessError> {
        self.view.node_directed_ring_pair_mut(
            node_slot,
            first_src_slot,
            first_dst_slot,
            second_src_slot,
            second_dst_slot,
        )
    }

    /// Borrows the owned coverage ring for one VM.
    ///
    /// Delegates to [`MappedSetupView::coverage_ring_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn coverage_ring_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedCoverageRingMut<'_>, MappedSetupRegionAccessError> {
        self.view.coverage_ring_mut(vm_slot)
    }

    /// Borrows the owned marker ring for one VM.
    ///
    /// Delegates to [`MappedSetupView::whitebox_marker_ring_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn whitebox_marker_ring_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedWhiteboxMarkerRingMut<'_>, MappedSetupRegionAccessError> {
        self.view.whitebox_marker_ring_mut(vm_slot)
    }

    /// Borrows the owned selectable reply ring for one VM.
    ///
    /// Delegates to [`MappedSetupView::selectable_reply_ring_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn selectable_reply_ring_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedSelectableReplyRingMut<'_>, MappedSetupRegionAccessError> {
        self.view.selectable_reply_ring_mut(vm_slot)
    }

    /// Borrows host roles in the owned request and response rings.
    ///
    /// Delegates to [`MappedSetupView::host_guest_introspection_rings_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn host_guest_introspection_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedHostGuestIntrospectionRingsMut<'_>, MappedSetupRegionAccessError> {
        self.view.host_guest_introspection_rings_mut(vm_slot)
    }

    /// Borrows plugin roles in the owned request and response rings.
    ///
    /// Delegates to [`MappedSetupView::plugin_guest_introspection_rings_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn plugin_guest_introspection_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedPluginGuestIntrospectionRingsMut<'_>, MappedSetupRegionAccessError> {
        self.view.plugin_guest_introspection_rings_mut(vm_slot)
    }

    /// Borrows plugin roles in the owned accelerator rings.
    ///
    /// Delegates to [`MappedSetupView::plugin_accelerator_rings_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn plugin_accelerator_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedPluginAcceleratorRingsMut<'_>, MappedSetupRegionAccessError> {
        self.view.plugin_accelerator_rings_mut(vm_slot)
    }

    /// Borrows host roles in the owned accelerator rings.
    ///
    /// Delegates to [`MappedSetupView::host_accelerator_rings_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn host_accelerator_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedHostAcceleratorRingsMut<'_>, MappedSetupRegionAccessError> {
        self.view.host_accelerator_rings_mut(vm_slot)
    }

    /// Borrows the owned fault-command transport for one VM.
    ///
    /// Delegates to [`MappedSetupView::fault_command_transport_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn fault_command_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultCommandTransportMut<'_>, MappedSetupRegionAccessError> {
        self.view.fault_command_transport_mut(vm_slot)
    }

    /// Borrows the owned fault-result transport for one VM.
    ///
    /// Delegates to [`MappedSetupView::fault_result_transport_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn fault_result_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultResultTransportMut<'_>, MappedSetupRegionAccessError> {
        self.view.fault_result_transport_mut(vm_slot)
    }

    /// Borrows the owned fault-event transport for one VM.
    ///
    /// Delegates to [`MappedSetupView::fault_event_transport_mut`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn fault_event_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultEventTransportMut<'_>, MappedSetupRegionAccessError> {
        self.view.fault_event_transport_mut(vm_slot)
    }

    /// Restores a held canonical ring image into the owned mapping.
    ///
    /// Delegates to [`MappedSetupView::restore_hot_fork_ring_image`] without exposing its ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns the same checked geometry, state or capacity refusal as the wire accessor.
    #[inline]
    pub fn restore_hot_fork_ring_image(
        &mut self,
        image: &HotForkRingImage,
    ) -> Result<(), HotForkRingImageError> {
        self.view.restore_hot_fork_ring_image(image)
    }
}
