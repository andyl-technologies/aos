//! Enters the restricted Recover command before handle/auth/model observation.
//!
//! A distinct authorized metadata completion can close the proved public CAS.
//! It never enters ordinary ownership retry or effect dispatch. The whole
//! attempt remains on the same Controller Journal after either outcome.

use super::*;
use std::sync::{Arc, Mutex};
use crate::controller_resource_reservation::{OperatorCreateRecoveryOriginalV1,
    OperatorCreateRecoveryClosedV1};

impl<C: ActivatedOperationCompiler, E: SingleNodeEffectExecutor> NodeController<C, E> {
    /// Borrows the selected actual Recover failure without changing its custody.
    #[doc(hidden)]
    pub fn operator_create_recovery_failure_view_v1(&mut self) -> Option<impl std::fmt::Display + '_> {
        self.reconciler.journal_mut().operator_recover_original_mut_v1()?.failure_view_v1()
    }

    /// Completes only independently proved Create metadata under a new Recover.
    ///
    /// # Errors
    /// Retains wrong request/target, failed original finance, authorization,
    /// inventory, currentness and independently owed native post refusals.
    #[doc(hidden)]
    pub fn observe_public_create_recovery_once_v1(&mut self,
        bank: &Arc<Mutex<crate::ControllerResourceBankOpeningV1>>,
        profile: &Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        runtime: &Arc<tokio::runtime::Runtime>,
        peer: &crate::public_api_session::PublicApiPeer,
        capability: aos_sandbox_model::CapabilityId, handle: &[u8], encoded: &[u8],
    ) -> Result<aos_sandbox_api::aos::sandbox::v1::Operation, OperatorCreateRecoveryClosedV1> {
        let request_scope = self.scope;
        let journal = self.reconciler.journal_mut();
        if journal.operator_recover_entry_is_occupied_v2() {
            return journal.read_completed_recover_retry_once_v1(
                peer, capability, handle, encoded, request_scope,
            );
        }
        let reached = OperatorCreateRecoveryOriginalV1::request_receiving_demand_v1(journal, peer, encoded)
            .map_err(|_|OperatorCreateRecoveryClosedV1)?;
        let original = OperatorCreateRecoveryOriginalV1::begin_native_v1(
            Arc::clone(bank), Arc::clone(profile), Arc::clone(runtime), journal, reached,
        );
        if let Err(original) = journal.install_operator_recover_entry_v2(original) {
            let _retained_original = original;
            std::process::abort();
        }
        if journal.operator_recover_original_mut_v1().is_none() {
            return Err(OperatorCreateRecoveryClosedV1);
        }
        let authorization = journal.authorize_operator_create_recovery_once_v1(peer, capability, handle, encoded);
        let mut original = journal.take_operator_recover_v1().ok_or(OperatorCreateRecoveryClosedV1)?;
        let admission = authorization.and_then(|()| original.append_observation_admission_once_v1(journal, request_scope));
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1 as Purpose;
        let purpose = match admission {
            Ok(()) => original.recovery_purpose_data_v1(journal).map_err(|_| OperatorCreateRecoveryClosedV1),
            Err(cause) => Err(cause),
        };
        let mut body = match purpose {
            Ok(Purpose::MetadataComplete | Purpose::StopCleanup | Purpose::ExecutionNoApply) =>
                self.reconciler.observe_operator_create_recovery_sources_v1(&mut original),
            Ok(Purpose::Ordinary) | Err(_) => Err(OperatorCreateRecoveryClosedV1),
        };
        if body.is_ok() && matches!(purpose, Ok(Purpose::MetadataComplete)) {
            // The sole existing public renderer runs inside this same native
            // interval and its already-paid closed response geometry. Only
            // the owned response crosses out after all independent posts.
            body = original.prepare_metadata_public_response_once_v1(self.reconciler.journal_mut());
        }
        original.retain_observation_result_v1(body);
        // The concrete inventory hook runs its Source/endpoint afters before
        // returning; these prearmed C posts remain owed after every body error.
        let after = original.finish_native_once_v1(self.reconciler.journal_mut());
        let disposition = self.reconciler.finish_operator_create_recovery_after_native_v1(&mut original);
        original.finish_final_clock_once_v1();
        let complete = body.is_ok() && after.is_ok() && disposition.is_ok()
            && original.failure_v1().is_none();
        if complete && matches!(purpose, Ok(Purpose::MetadataComplete)) {
            // Historical metadata completion is independent of a subsequent
            // no-active observation. The executor retains its entire entered
            // result; only a separate sealed reconciliation/enrollment may
            // permit ordinary service. A refusal never relabels this operation.
            let _physical_observation = self.reconciler
                .reconcile_first_local_after_recover_v2(&original);
        }
        let response = match (complete, purpose) {
            (true, Ok(Purpose::MetadataComplete)) =>
                original.take_completed_metadata_public_response_v1(self.reconciler.journal_mut()),
            (true, Ok(purpose @ (Purpose::StopCleanup | Purpose::ExecutionNoApply))) => {
                // Only finance and passive observation have completed here.
                // Public Recover stays pending while the fresh concrete payer
                // obtains its independent Root grant and performs cleanup.
                self.reconciler.complete_operator_cleanup_recovery_v2(&mut original, purpose)
                    .and_then(|response| {
                        original.require_completed_cleanup_response_data_v2(
                            self.reconciler.journal_mut(), purpose, &response)?;
                        Ok(response)
                    })
            }
            _ => Err(OperatorCreateRecoveryClosedV1),
        };
        if response.is_err() {
            original.fence_metadata_after_refusal_once_v1(self.reconciler.journal_mut());
        }
        if let Err(original) = self.reconciler.journal_mut().install_operator_recover_v1(original) {
            let _retained_original = original;
            std::process::abort();
        }
        response
    }
}

impl crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1 {
    pub(crate) fn authorize_completed_operation_read_v1(
        &mut self,
        controller: &mut crate::Journal,
        peer: &crate::public_api_session::PublicApiPeer,
        capability: aos_sandbox_model::CapabilityId,
        scope: &crate::PublicOperationAuthorizationV1,
        protobuf_body: &[u8],
    ) -> Result<(
        crate::cli_model::AuditAuthorizationV1,
        crate::cli_model::authorization_adapter::CurrentCapabilityDecisionV1,
    ), crate::cli_model::authorization_adapter::CliAuthorizationAdapterError> {
        super::public_api_authorization::authorize_public_operation_read_retaining_v1(
            controller, peer, capability, scope, protobuf_body, self,
        )
    }
}
