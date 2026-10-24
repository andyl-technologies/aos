//! Retains a genuine consumed suffix member before constructing Source15.
//!
//! The old nested Source14/15 grammars remain unchanged. Only the distinct
//! launch7/preamble16 writer carries the independently admitted reservation.
//! Neither this member nor its row enables a native Endpoint or Capture codec.

use super::*;
use crate::node_admission::OriginalRestoredSuffixStartupMember;
use crucible_node_transport::reference_packet::service::native_startup::PacketRestoredSuffixReservationData;
use std::cell::{BorrowError, Ref};

impl PacketCompleteSemanticSource {
    pub(crate) fn finalize_original_restored_suffix_startup_birth(
        self: &Rc<Self>,
        member: OriginalNativeStartupMember,
        launch: &PacketNative5SourceLaunch,
        purpose: &crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData,
    ) -> Result<(), RuntimeError> {
        member.authenticate(self)?;
        let suffix = member
            .suffix
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        suffix.authenticate_source_data(self)?;
        if !self.is_original_restored_suffix_declaration_data()?
            || purpose.is_original_execution_data()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // The existing finalizer stores this complete member, including its
        // non-Clone suffix owner, before any fallible bank or DOM construction.
        self.finalize_original_native_invocation_birth(member, launch, purpose)
    }

    /// Borrows the reservation only after the actual host startup16 write.
    ///
    /// This lifecycle DATA does not prove native receipt, first publication or
    /// an admitted action. The Source action wrapper separately keeps its
    /// owning SourceRead armed while authenticating this loan and its terminal
    /// member fence. No nested association or current-read loan is acquired.
    ///
    /// # Errors
    /// Refuses foreign origin, a different declaration, incomplete private
    /// birth or startup, an expired member and attempted-only wire publication.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_completed_restored_suffix_startup_data(
        &self,
    ) -> Result<PacketRestoredSuffixReservationData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !self.is_original_restored_suffix_declaration_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }

        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.authenticate_original_initial_lifecycle_data()?;
        let state = birth
            .native_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !state.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        state.member.authenticate_boot_ready(self)?;

        let suffix = state
            .member
            .suffix
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        suffix.authenticate_completed_wire_data(self)?;
        Ok(suffix.reservation_data())
    }

    /// Lends the actual immutable startup geometry to a new observation quote.
    ///
    /// This is the same completed host-wire owner, never a native receipt or
    /// action grant. The effect caller separately holds the owning SourceRead.
    ///
    /// # Errors
    /// Refuses foreign origin, absent declaration/birth, unready member or an
    /// incomplete startup16 publication. No fallback geometry is reconstructed.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_restored_suffix_observation_startup_data(
        &self,
    ) -> Result<crucible_node_transport::reference_packet::service::native_startup::PacketNativeRestoredSuffixStartupStorageData, RuntimeError>{
        self.storage_origin_with_error::<RuntimeError>()?;
        if !self.is_original_restored_suffix_declaration_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.authenticate_original_initial_lifecycle_data()?;
        let state = birth
            .native_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !state.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        state.member.authenticate_boot_ready(self)?;
        state
            .member
            .suffix
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .observation_startup_data(self)
    }

    /// Counts the complete distinct wire owner independently of its raw banks.
    pub fn original_restored_suffix_wire_header_storage_data() -> usize {
        super::super::native_wire::original_restored_suffix_wire_counter_scratch_data()
            + size_of::<super::super::native_wire::PacketCompleteNativeRestoredSuffixStartupWire>()
            + size_of::<
                Option<super::super::native_wire::PacketCompleteNativeRestoredSuffixStartupWire>,
            >()
    }

    /// Names exact new Source loans, fixed headers and actual writer views.
    ///
    /// # Errors
    /// Refuses checked layout overflow before declaration or member inspection.
    pub fn original_restored_suffix_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms: [usize; 28] = [
            Self::original_restored_suffix_declaration_counter_scratch_data(),
            Self::original_native_invocation_source_counter_scratch_data()?,
            super::super::native_wire::original_restored_suffix_wire_counter_scratch_data(),
            size_of::<&OriginalRestoredSuffixStartupMember>(),
            size_of::<Option<&OriginalRestoredSuffixStartupMember>>(),
            size_of::<Result<&OriginalRestoredSuffixStartupMember, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<bool, RuntimeError>>(),
            size_of::<&PacketCompleteSemanticSource>(),
            size_of::<&OriginalNativeStartupMember>(),
            size_of::<[usize; 28]>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<&[usize]>(),
            size_of::<std::array::IntoIter<usize, 28>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Ref<'static, Option<OriginalAckPeerBirth>>>(),
            size_of::<Result<Ref<'static, Option<OriginalAckPeerBirth>>, BorrowError>>(),
            size_of::<Result<Ref<'static, Option<OriginalAckPeerBirth>>, RuntimeError>>(),
            size_of::<Option<&OriginalAckPeerBirth>>(),
            size_of::<Result<&OriginalAckPeerBirth, RuntimeError>>(),
            size_of::<&OriginalNativeStartupFinalization>(),
            size_of::<Option<&OriginalNativeStartupFinalization>>(),
            size_of::<Result<&OriginalNativeStartupFinalization, RuntimeError>>(),
            size_of::<PacketRestoredSuffixReservationData>(),
            size_of::<Result<PacketRestoredSuffixReservationData, RuntimeError>>(),
            size_of::<BorrowError>(),
            size_of::<super::super::OriginalAckPeerInputs<'static>>(),
            size_of::<Result<super::super::OriginalAckPeerInputs<'static>, RuntimeError>>(),
        ];
        retained_values::sum_with_error::<RuntimeError, _>(terms, usize::MAX)
    }
}

impl PacketCompleteSemanticSource {
    /// Authenticates the same completed birth's typed and complete nested launch.
    ///
    /// This borrowed identity check spends no wire, bootstrap or action marker.
    /// The real phase claim and owning SourceRead remain separate conjuncts.
    ///
    /// # Errors
    /// Refuses another typed launch, purpose, Source/member, incomplete original
    /// wire, changed complete raw launch bytes or the defining wrapper ceiling.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_original_restored_producer_launch_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_launch_data(launch)?;
        if !self.is_original_restored_suffix_declaration_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.authenticate_original_initial_lifecycle_data()?;
        let state = birth
            .native_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !state.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        state.member.authenticate_boot_ready(self)?;
        let purpose = state
            .original_invocation_data()?
            .ok_or(RuntimeError::OwnerUnavailable)?;
        purpose
            .authenticate_target_data(launch)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let suffix = state
            .member
            .suffix
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        suffix.authenticate_source_data(self)?;
        suffix.authenticate_completed_wire_data(self)?;
        let reservation = suffix.reservation_data();
        // Dispatch from the actual private retained member, never a DTO/tag or
        // a failed old parser fallback. Each family binds its complete wrapper.
        if let Some(settled) = suffix.settled_data(self)? {
            if !self.is_original_restored_settled_capture_declaration_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
            let actual=crucible_node_transport::reference_packet::service::native_startup::original_native_settled_launch_identity_data(
                &purpose,canonical_launch5,&reservation,settled.existing_rows_data(),settled.carrier_data()).map_err(|_|RuntimeError::ForeignAuthority)?;
            if actual != settled.launch_identity_data() || actual.encoded_bytes > 1024 * 1024 {
                return Err(RuntimeError::ForeignAuthority);
            }
        } else {
            let actual = crucible_node_transport::reference_packet::service::native_startup::original_native_suffix_launch_identity_data(
                &purpose, canonical_launch5, &reservation,
            ).map_err(|_| RuntimeError::ForeignAuthority)?;
            if actual != suffix.launch_identity_data() || actual.encoded_bytes > 1024 * 1024 {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Ok(())
    }

    /// Names startup authentication and the exact borrowed identity views.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_restored_producer_launch_counter_scratch_data()
    -> usize {
        use crucible_node_transport::reference_packet::service::native_startup::{
            PacketNativeInvocationPurposeData, PacketNativeSuffixLaunchIdentityData,
            original_native_suffix_counter_scratch_data,
        };
        crucible_node_transport::reference_packet::service::native_startup::original_native_settled_carrier_counter_scratch_data()
            + size_of::<Option<&crate::node_admission::OriginalRestoredSettledStartupMember>>()
            + size_of::<Result<Option<&crate::node_admission::OriginalRestoredSettledStartupMember>, RuntimeError>>()
            + super::super::PacketCompleteAckPeerBootMaterial::original_native_startup_authentication_scratch_data()
            + original_native_suffix_counter_scratch_data()
            + size_of::<PacketNativeInvocationPurposeData>()
            + size_of::<Option<PacketNativeInvocationPurposeData>>()
            + size_of::<Result<Option<PacketNativeInvocationPurposeData>, RuntimeError>>()
            + size_of::<Result<PacketNativeInvocationPurposeData, RuntimeError>>()
            + size_of::<PacketNativeSuffixLaunchIdentityData>()
            + size_of::<Result<PacketNativeSuffixLaunchIdentityData, crucible_node_transport::ProviderError>>()
            + size_of::<&OriginalNativeStartupFinalization>()
            + size_of::<Option<&OriginalNativeStartupFinalization>>()
            + size_of::<Result<&OriginalNativeStartupFinalization, RuntimeError>>()
            + size_of::<&OriginalRestoredSuffixStartupMember>()
            + size_of::<Option<&OriginalRestoredSuffixStartupMember>>()
            + size_of::<Result<&OriginalRestoredSuffixStartupMember, RuntimeError>>()
            + size_of::<PacketRestoredSuffixReservationData>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<(), crucible_node_transport::ProviderError>>()
            + size_of::<&PacketNative5SourceLaunch>() + size_of::<&[u8]>()
    }
}
