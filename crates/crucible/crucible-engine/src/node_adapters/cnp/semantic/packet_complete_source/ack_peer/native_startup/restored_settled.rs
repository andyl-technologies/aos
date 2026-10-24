//! Retains a genuine native17 member before unchanged nested Source15 work.
//!
//! Host wire completion is a prerequisite, not native receipt or an actual
//! Prepare/current-state/Capture proof. Those independent live owners remain
//! mandatory at their respective SourceRead/Window/SDK call sites.

use super::*;
use crucible_node_transport::reference_packet::service::native_startup::{
    PacketRestoredSettledNativeCarrierData, PacketRestoredSettledNativeExistingRowsData,
    PacketRestoredSettledNativeStorageData,
};

impl PacketCompleteSemanticSource {
    pub(crate) fn finalize_original_restored_settled_startup_birth(
        self: &Rc<Self>,
        member: OriginalNativeStartupMember,
        launch: &PacketNative5SourceLaunch,
        purpose:&crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData,
    ) -> Result<(), RuntimeError> {
        member.authenticate(self)?;
        if !self.is_original_restored_settled_capture_declaration_data()?
            || purpose.is_original_execution_data()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        member
            .suffix
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .settled_data(self)?
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.finalize_original_native_invocation_birth(member, launch, purpose)
    }

    /// Copies the actual completed17 member's exact reservation DATA.
    ///
    /// # Errors
    /// Refuses a foreign/expired member, absent explicit declaration, incomplete
    /// Source/private birth or failed/partial host publication. It does not
    /// acquire a SourceRead or infer native receipt or an admitted Capture row.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_completed_restored_settled_startup_data(
        &self,
    ) -> Result<PacketRestoredSettledNativeCarrierData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !self.is_original_restored_settled_capture_declaration_data()? {
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
        let suffix = state
            .member
            .suffix
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let settled = suffix
            .settled_data(self)?
            .ok_or(RuntimeError::OwnerUnavailable)?;
        settled.authenticate_completed_wire_data()?;
        Ok(*settled.carrier_data())
    }

    /// Lends the actual non-Copy preChild native quote under the same private member.
    ///
    /// This synchronous DATA loan neither reconstructs numeric StorageData nor
    /// renews a native reserve. The Source independently funds its decoder row
    /// from this defining quote and retains only its own admitted result. Full
    /// SourceRead/ticket/native proof checks remain separate before effects.
    ///
    /// # Errors
    /// Refuses wrong origin/selection/member, incomplete private birth or host
    /// publication, callback refusal, or changed correspondence after the loan.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn with_original_completed_restored_settled_startup_data<
        R,
    >(
        &self,
        inspect: impl for<'row> FnOnce(
            &'row PacketRestoredSettledNativeStorageData,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !self.is_original_restored_settled_capture_declaration_data()? {
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
        let suffix = state
            .member
            .suffix
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let settled = suffix
            .settled_data(self)?
            .ok_or(RuntimeError::OwnerUnavailable)?;
        settled.authenticate_completed_wire_data()?;
        let result = inspect(settled.storage_data());
        self.storage_origin_with_error::<RuntimeError>()?;
        state.member.authenticate_boot_ready(self)?;
        settled.authenticate_completed_wire_data()?;
        result
    }

    /// Counts the complete new wire owner independently of dynamic wire banks.
    pub fn original_restored_settled_wire_header_storage_data() -> usize {
        super::super::native_wire::original_restored_settled_wire_counter_scratch_data()
            + size_of::<super::super::native_wire::PacketCompleteNativeRestoredSettledStartupWire>()
            + size_of::<
                Option<super::super::native_wire::PacketCompleteNativeRestoredSettledStartupWire>,
            >()
    }

    /// Names actual defining Source/member/Provider fixed views before quote.
    ///
    /// # Errors
    /// Refuses checked fixed-view overflow before entering the actual birth.
    pub fn original_restored_settled_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        use std::cell::{BorrowError, Ref};
        let terms=[Self::original_restored_suffix_startup_counter_scratch_data()?,
            Self::original_restored_settled_capture_declaration_counter_scratch_data(),
            super::super::native_wire::original_restored_settled_wire_counter_scratch_data(),
            size_of::<&crate::node_admission::OriginalRestoredSettledStartupMember>(),
            size_of::<Option<&crate::node_admission::OriginalRestoredSettledStartupMember>>(),
            size_of::<Result<Option<&crate::node_admission::OriginalRestoredSettledStartupMember>,RuntimeError>>(),
            size_of::<Result<&crate::node_admission::OriginalRestoredSettledStartupMember,RuntimeError>>(),
            size_of::<&PacketRestoredSettledNativeCarrierData>(),size_of::<PacketRestoredSettledNativeCarrierData>(),
            size_of::<Result<PacketRestoredSettledNativeCarrierData,RuntimeError>>(),
            size_of::<Ref<'static,Option<OriginalAckPeerBirth>>>(),
            size_of::<Result<Ref<'static,Option<OriginalAckPeerBirth>>,BorrowError>>(),
            size_of::<Result<Ref<'static,Option<OriginalAckPeerBirth>>,RuntimeError>>(),
            size_of::<Option<&OriginalAckPeerBirth>>(),size_of::<Result<&OriginalAckPeerBirth,RuntimeError>>(),
            size_of::<Option<&OriginalNativeStartupFinalization>>(),size_of::<Result<&OriginalNativeStartupFinalization,RuntimeError>>(),
            size_of::<Result<(),RuntimeError>>(),size_of::<Result<bool,RuntimeError>>(),size_of::<Result<usize,RuntimeError>>(),
            size_of::<&PacketRestoredSettledNativeStorageData>(),size_of::<&PacketRestoredSettledNativeExistingRowsData>(),
            size_of::<crucible_node_transport::reference_packet::service::native_startup::PacketRestoredSettledNativeOutputValidationStorageData>(),
            size_of::<Result<crucible_node_transport::reference_packet::service::native_startup::PacketRestoredSettledNativeOutputValidationStorageData,crucible_node_transport::ProviderError>>()];
        let headers = std::mem::size_of_val(&terms)
            .checked_add(std::mem::size_of_val(&terms.into_iter()))
            .ok_or(RuntimeError::ResourceLimit)?;
        retained_values::sum_with_error::<RuntimeError, _>(terms, usize::MAX)?
            .checked_add(headers)
            .ok_or(RuntimeError::ResourceLimit)
    }
}
