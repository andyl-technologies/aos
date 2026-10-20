//! Queries the four actual Runtime Sessions under one authorized C17/Source cut.
//!
//! The common Security query owns the Session while every existing Runtime
//! dependent remains on this stack or its original Host shell. Positive query
//! completion restores the same Session; no cold opener, retirement/reconnect,
//! dependency drop or fabricated six-cut is substituted.

use super::*;
use aos_sandbox_controller_domain::{
    ControllerDeleteSourceAuthorizedScopeV1, ControllerResourceBankOpeningV1,
    DeleteInventorySessionAppendOriginalV1, Journal, ResourceReservationErrorV1,
};
use aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1;
use aos_sandbox_broker_session_security::controller_composition::{
    DeleteInventoryAnswerOriginalsV1, OriginalDeleteInventoryClientV1,
    StoragePreparationClientProgressV1,
};

/// Selects only the genuine authorized planning or ACK-gated Pending source.
/// Both variants enter the same paid Session/native query engine.
pub(in crate::controller_service) enum ControllerDeleteInventorySourceV2<
    'source, 'scope, 'original, 'challenge,
> {
    Planning(&'source mut ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>),
    Pending {
        pending: &'source mut aos_sandbox_controller_domain::ControllerDeletePendingOriginalV2<'scope, 'original>,
        challenge: &'source aos_sandbox_controller_domain::ControllerDeletePendingRootChallengeLoanV2<'challenge>,
    },
}

impl<'scope, 'original> ControllerDeleteInventorySourceV2<'_, 'scope, 'original, '_> {
    pub(in crate::controller_service) fn reserve_model_bytes_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        bytes: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Planning(authorized) => bank.reserve_delete_planning_collection_v2(
                authorized, controller, profile, bytes,
            ),
            Self::Pending { pending, challenge } => bank.reserve_delete_pending_collection_v2(
                pending, controller, profile, challenge, bytes,
            ),
        }
    }

    pub(in crate::controller_service) fn borrow_native_once_v2<'turn, 'profile>(
        &'turn mut self,
        bank: &'turn ControllerResourceBankOpeningV1,
        controller: &'turn mut Journal,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        session: &DormantAuthenticatedBrokerSessionV1,
        construction_bytes: usize,
    ) -> Result<DeleteInventorySessionAppendOriginalV1<
        'turn, 'turn, 'scope, 'original, 'scope, 'profile,
    >, ResourceReservationErrorV1> {
        match self {
            Self::Planning(authorized) => OriginalDeleteInventoryClientV1::borrow_planning_native_once_v1(
                bank, authorized, controller, profile, session, construction_bytes,
            ),
            Self::Pending { pending, challenge } => OriginalDeleteInventoryClientV1::borrow_pending_native_once_v2(
                bank, pending, controller, profile, session, challenge, construction_bytes,
            ),
        }
    }
}

/// Runs the sole Security state machine without shedding negative custody.
///
/// Every returned positive Session/model crossed native disposition. On an
/// entered failure the query's independently owed final posts run first, then
/// termination occurs while the whole query and the caller's Runtime shell are
/// still resident. There is no replacement request or error-to-success path.
pub(in crate::controller_service) fn complete_query_once_v1(
    native: DeleteInventorySessionAppendOriginalV1<'_, '_, '_, '_, '_, '_>,
    session: DormantAuthenticatedBrokerSessionV1,
) -> (DormantAuthenticatedBrokerSessionV1, DeleteInventoryAnswerOriginalsV1) {
    let mut query = OriginalDeleteInventoryClientV1::retain_prepaid(native, session);
    let prepared = query.prepare_once();
    let mut committed = false;
    if prepared.is_ok() {
        loop {
            match query.advance_once() {
                StoragePreparationClientProgressV1::Committed => {
                    committed = true;
                    break;
                }
                StoragePreparationClientProgressV1::Closed => break,
                StoragePreparationClientProgressV1::Pending
                    | StoragePreparationClientProgressV1::Sent => {}
            }
        }
    }
    let posted = query.finish_native_once();
    if prepared.is_err() || !committed || posted.is_err() {
        let _ = query.finish_outer_source_failure_once_v1();
        std::process::abort();
    }
    query.finish_positive_once()
}

fn runtime_construction_bytes_v1() -> Result<usize, ResourceReservationErrorV1> {
    // The actual Session container is moved through a local, a destructured
    // set of the SAME dependent owners and its restored positive destination.
    // Security separately pays its own query, answer and per-IO construction.
    std::mem::size_of::<DormantLifecycleInventorySessionV1>().checked_mul(3)
        .ok_or(ResourceReservationErrorV1::Conflict)
}

impl crate::controller_service::ControllerBrokerSessions {
    /// Parks each whole successful answer before entering the next real query.
    ///
    /// The enclosing prepaid collection owns these destinations. A later
    /// admission failure therefore leaves all earlier answers resident through
    /// the enclosing Source/C17 owed posts; no partial array is unwound by `?`.
    pub(in crate::controller_service) fn collect_delete_planning_sessions_once_v1(
        &mut self,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        answers: &mut [Option<DeleteInventoryAnswerOriginalsV1>; 4],
        stages: &mut [Option<Result<(), ResourceReservationErrorV1>>; 6],
    ) -> Result<(), ResourceReservationErrorV1> {
        let mut source = ControllerDeleteInventorySourceV2::Planning(authorized);
        self.collect_delete_sessions_from_source_once_v2(
            &mut source, bank, controller, profile, answers, stages,
        )
    }

    pub(in crate::controller_service) fn collect_delete_sessions_from_source_once_v2(
        &mut self,
        source: &mut ControllerDeleteInventorySourceV2<'_, '_, '_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        answers: &mut [Option<DeleteInventoryAnswerOriginalsV1>; 4],
        stages: &mut [Option<Result<(), ResourceReservationErrorV1>>; 6],
    ) -> Result<(), ResourceReservationErrorV1> {
        stages[0] = Some(retain_planning_answer_v2(&mut answers[0],
            self.host.as_mut().ok_or(ResourceReservationErrorV1::Conflict)
                .and_then(|host| host.query_delete_from_source_once_v2(source, bank, controller, profile))));
        if !matches!(stages[0], Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }

        stages[1] = Some(retain_planning_answer_v2(&mut answers[1],
            self.query_delete_mount_from_source_once_v2(source, bank, controller, profile)));
        if !matches!(stages[1], Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }

        stages[2] = Some(retain_planning_answer_v2(&mut answers[2],
            self.query_delete_storage_from_source_once_v2(source, bank, controller, profile)));
        if !matches!(stages[2], Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }

        stages[3] = Some(retain_planning_answer_v2(&mut answers[3],
            self.query_delete_network_from_source_once_v2(source, bank, controller, profile)));
        if !matches!(stages[3], Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }
}

impl crate::controller_service::ControllerBrokerSessions {
    fn query_delete_mount_from_source_once_v2(
        &mut self,
        source: &mut ControllerDeleteInventorySourceV2<'_, '_, '_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<DeleteInventoryAnswerOriginalsV1, ResourceReservationErrorV1> {
        let original = self.mount.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        storage_preparation_client::OriginalStoragePreparationClientV1::require_idle(&original.0)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let native = source.borrow_native_once_v2(
            bank, controller, profile, &original.0.session, runtime_construction_bytes_v1()?,
        )?;
        // No move or extra Runtime construction precedes the actual C17 debit.
        let DormantMountLifecycleInventoryOwnerV1(original) = match self.mount.take() {
            Some(original) => original,
            None => std::process::abort(),
        };
        let DormantLifecycleInventorySessionV1 {
            capture_candidate, session, pending, authority_effects, output_registration,
            capture_admission, capture_admission_construction,
            #[cfg(feature = "online-nix")]
            nix_generation,
            git_coverage,
        } = original;
        let (session, answer) = complete_query_once_v1(native, session);
        self.mount = Some(DormantMountLifecycleInventoryOwnerV1(DormantLifecycleInventorySessionV1 {
            capture_candidate, session, pending, authority_effects, output_registration,
            capture_admission, capture_admission_construction,
            #[cfg(feature = "online-nix")]
            nix_generation,
            git_coverage,
        }));
        Ok(answer)
    }
}

impl crate::controller_service::ControllerBrokerSessions {
    fn query_delete_storage_from_source_once_v2(
        &mut self,
        source: &mut ControllerDeleteInventorySourceV2<'_, '_, '_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<DeleteInventoryAnswerOriginalsV1, ResourceReservationErrorV1> {
        let original = self.storage.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        storage_preparation_client::OriginalStoragePreparationClientV1::require_idle(&original.0)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if self.storage_cold.as_ref().is_some_and(|cold| cold.is_failed())
            || self.storage_root.has_pending() || self.storage_root.requires_reconnect()
            || self.storage_preparation_client.is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = source.borrow_native_once_v2(
            bank, controller, profile, &original.0.session, runtime_construction_bytes_v1()?,
        )?;
        // No move or extra Runtime construction precedes the actual C17 debit.
        let DormantStorageLifecycleInventoryOwnerV1(original) = match self.storage.take() {
            Some(original) => original,
            None => std::process::abort(),
        };
        let DormantLifecycleInventorySessionV1 {
            capture_candidate, session, pending, authority_effects, output_registration,
            capture_admission, capture_admission_construction,
            #[cfg(feature = "online-nix")]
            nix_generation,
            git_coverage,
        } = original;
        let (session, answer) = complete_query_once_v1(native, session);
        self.storage = Some(DormantStorageLifecycleInventoryOwnerV1(DormantLifecycleInventorySessionV1 {
            capture_candidate, session, pending, authority_effects, output_registration,
            capture_admission, capture_admission_construction,
            #[cfg(feature = "online-nix")]
            nix_generation,
            git_coverage,
        }));
        Ok(answer)
    }
}

impl crate::controller_service::ControllerBrokerSessions {
    fn query_delete_network_from_source_once_v2(
        &mut self,
        source: &mut ControllerDeleteInventorySourceV2<'_, '_, '_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<DeleteInventoryAnswerOriginalsV1, ResourceReservationErrorV1> {
        let original = self.network.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        storage_preparation_client::OriginalStoragePreparationClientV1::require_idle(&original.0)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let native = source.borrow_native_once_v2(
            bank, controller, profile, &original.0.session, runtime_construction_bytes_v1()?,
        )?;
        // No move or extra Runtime construction precedes the actual C17 debit.
        let DormantNetworkLifecycleInventoryOwnerV1(original) = match self.network.take() {
            Some(original) => original,
            None => std::process::abort(),
        };
        let DormantLifecycleInventorySessionV1 {
            capture_candidate, session, pending, authority_effects, output_registration,
            capture_admission, capture_admission_construction,
            #[cfg(feature = "online-nix")]
            nix_generation,
            git_coverage,
        } = original;
        let (session, answer) = complete_query_once_v1(native, session);
        self.network = Some(DormantNetworkLifecycleInventoryOwnerV1(DormantLifecycleInventorySessionV1 {
            capture_candidate, session, pending, authority_effects, output_registration,
            capture_admission, capture_admission_construction,
            #[cfg(feature = "online-nix")]
            nix_generation,
            git_coverage,
        }));
        Ok(answer)
    }
}

impl super::DormantNetworkLifecycleInventoryOwnerV1 {
    pub(in crate::controller_service) fn delete_network_shape_v4(&self, request_bytes: usize)
        -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        self.0.session.delete_network_apply_shape_v4(request_bytes)
    }

    pub(in crate::controller_service) fn run_delete_network_apply_once_v4(&mut self,
        sdk: &mut aos_sandbox_broker_session_security::controller_composition::DeleteNetworkApplySessionIoOriginalV4,
        loan: &mut aos_sandbox_controller_domain::OriginalDeleteNetworkApplyLoanV4<'_>,
        predecessor: &DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1> {
        sdk.apply_once_v4(&mut self.0.session, loan, predecessor)
    }

    pub(in crate::controller_service) fn retire_delete_network_apply_window_once_v4(&mut self,
        sdk: &mut aos_sandbox_broker_session_security::controller_composition::DeleteNetworkApplySessionIoOriginalV4,
        loan: &mut aos_sandbox_controller_domain::OriginalDeleteNetworkApplyLoanV4<'_>,
    ) -> Result<(), aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1> {
        sdk.retire_completed_native_window_once_v4(&mut self.0.session, loan)
    }
}

impl super::DormantMountLifecycleInventoryOwnerV1 {
    pub(in crate::controller_service) fn delete_mount_reap_shape_v4(&self, request_bytes: usize)
        -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        self.0.session.delete_mount_reap_shape_v4(request_bytes)
    }

    pub(in crate::controller_service) fn run_delete_mount_reap_once_v4(&mut self,
        sdk: &mut aos_sandbox_broker_session_security::controller_composition::DeleteMountReapSessionIoOriginalV4,
        loan: &mut aos_sandbox_controller_domain::OriginalDeleteMountReapLoanV4<'_>,
        predecessor: &DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1> {
        sdk.apply_once_v4(&mut self.0.session, loan, predecessor)
    }

    pub(in crate::controller_service) fn retire_delete_mount_reap_window_once_v4(&mut self,
        sdk: &mut aos_sandbox_broker_session_security::controller_composition::DeleteMountReapSessionIoOriginalV4,
        loan: &mut aos_sandbox_controller_domain::OriginalDeleteMountReapLoanV4<'_>,
    ) -> Result<(), aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1> {
        sdk.retire_completed_native_window_once_v4(&mut self.0.session, loan)
    }
}

// This is only an owning Result split into destinations of the prepaid frame.
// It cannot construct an answer from DATA or alter an original query error.
fn retain_planning_answer_v2(
    destination: &mut Option<DeleteInventoryAnswerOriginalsV1>,
    answer: Result<DeleteInventoryAnswerOriginalsV1, ResourceReservationErrorV1>,
) -> Result<(), ResourceReservationErrorV1> {
    match answer {
        Ok(answer) => { *destination = Some(answer); Ok(()) }
        Err(cause) => Err(cause),
    }
}

impl super::DormantStorageLifecycleInventoryOwnerV1 {
    pub(in crate::controller_service) fn run_delete_storage_preparation_once_v3(&mut self,
        sdk: &mut aos_sandbox_broker_session_security::controller_composition::DeleteStoragePreparationSessionIoOriginalV3,
        loan: &mut aos_sandbox_controller_domain::OriginalDeleteStoragePreparationLoanV3<'_>,
        answer: &DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1> {
        sdk.prepare_once_v3(&mut self.0.session, loan, answer)
    }

    pub(in crate::controller_service) fn retire_delete_storage_preparation_window_once_v3(&mut self,
        sdk: &mut aos_sandbox_broker_session_security::controller_composition::DeleteStoragePreparationSessionIoOriginalV3,
        loan: &mut aos_sandbox_controller_domain::OriginalDeleteStoragePreparationLoanV3<'_>,
    ) -> Result<(), aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1> {
        sdk.retire_completed_native_window_once_v3(&mut self.0.session, loan)
    }
}

impl super::DormantStorageLifecycleInventoryOwnerV1 {
    pub(in crate::controller_service) fn delete_preparation_shape_v3(&self, request_bytes: usize)
        -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        self.0.session.delete_storage_preparation_shape_v3(request_bytes)
    }

    pub(in crate::controller_service) fn delete_apply_shape_v3(&self, request_bytes: usize)
        -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        self.0.session.delete_storage_apply_shape_v3(request_bytes)
    }

    pub(in crate::controller_service) fn run_delete_storage_apply_once_v3(&mut self,
        sdk: &mut aos_sandbox_broker_session_security::controller_composition::DeleteStorageApplySessionIoOriginalV3,
        loan: &mut aos_sandbox_controller_domain::OriginalDeleteStorageApplyLoanV3<'_>,
        predecessor: &aos_sandbox_broker_session_security::controller_composition::DeleteStoragePreparationSessionIoOriginalV3,
    ) -> Result<(), aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1> {
        sdk.apply_once_v3(&mut self.0.session, loan, predecessor)
    }

    pub(in crate::controller_service) fn retire_delete_storage_apply_window_once_v3(&mut self,
        sdk: &mut aos_sandbox_broker_session_security::controller_composition::DeleteStorageApplySessionIoOriginalV3,
        loan: &mut aos_sandbox_controller_domain::OriginalDeleteStorageApplyLoanV3<'_>,
    ) -> Result<(), aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1> {
        sdk.retire_completed_native_window_once_v3(&mut self.0.session, loan)
    }
}
