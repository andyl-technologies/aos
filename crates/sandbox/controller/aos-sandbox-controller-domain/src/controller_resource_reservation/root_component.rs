//! Retains the original Root subdivision of the already-paid Components grant.
//!
//! R is one permanent purpose-13 claim, not a Root account or operation loan.
//! PID1 installs its whole-service bounds before exec, including the negative
//! prefix that authenticates these original image and delivery descriptors.
//! Native DATA never reconstructs that producer or refunds a dead invocation.

mod layout;
mod selected_startup;
mod service_observation;
mod root_journal;
mod credential_receiving;
mod current_writers;
mod policy_listener;
mod controller_peer;
mod delete_peer;
mod native_no_apply;
mod current_owned;
mod delete_exchange;
pub(crate) use delete_exchange::{RootStopCleanupChunkPostsV1, RootExecutionNoApplyChunkPostsV2, RootDeleteChunkPostsV1, RootApplyChunkPostsV1, RootStartAssignmentInputsChunkPostsV2, RootHostLaunchChunkPostsV2, RootMaintenanceStorageChunkPostsV2};
pub(crate) use delete_peer::{RootContinuationDemandV1, RootContinuationStageV1, RootStopCleanupStageV1, StopCleanupRootPeerPurposeV1, RootMaintenanceStorageStageV2, RootExecutionNoApplyReadPhaseV2, RootContinuationStagesV1, RootPurposePeerAdmissionV1, RootPurposePeerPostV1, RootPeerPurposeV1, DeleteRootPeerPurposeV1, EnvironmentRootPeerPurposeV1, ApplyRootPeerPurposeV1, HostLaunchRootPeerPurposeV1, MaintenanceStorageRootPeerPurposeV2, ExecutionNoApplyRootPeerPurposeV2, FinalityRecoverRootPeerPurposeV1, StartAssignmentInputsRootPeerPurposeV2};
mod current_open;
mod current_ready;
mod current_pins;
mod current_ownership_trust;
mod current_provision;
mod current_policy_inputs;
mod current_source_query;
mod current_source_exchange;
mod current_bundle_ownership;
mod current_cache_proof;
mod current_controller_readonly;
mod current_use_authorized;
mod current_use_reserved;
mod current_use_admitted;
mod current_signed_bound;
mod current_outcome;
mod current_closed;
mod journal_finance;
mod policy_flight;
mod q04_transport;

use std::error::Error;

use aos_sandbox_model::ResourceVector;

use super::ResourceReservationErrorV1;

// This owner captures only the current process's original four-role table.
// No descriptor, vector, observation or receipt argument constructs payment.
// The coarse caller error never replaces its owning native/canonical Result.
pub(crate) struct RootReceivingOriginalV1 {
    activation: aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1,
    native_receiving_refusal: Option<std::sync::Arc<ResourceReservationErrorV1>>,
    service_observations: service_observation::RootServiceObservationsV1,
    activation_names_refusal: Option<crate::normal_root::NormalRootStartupErrorV1>,
    role_error: Option<ResourceReservationErrorV1>,
    original: Option<Result<aos_sandbox_broker::receiving::OriginalEnrollment, ResourceReservationErrorV1>>,
    shape: Option<Result<(), ResourceReservationErrorV1>>,
    receiving_completion: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    recipient_binding: Option<Result<(), ResourceReservationErrorV1>>,
    selected: Option<crate::normal_root::RootSelectedStartupReceivingV1>,
    selected_completion: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    service_currentness: Option<crate::normal_root::RootServiceCurrentnessV1>,
    native_startup_prior: Option<aos_sandbox_policy::native::RootStartupProvisionOriginalV1>,
    native_completed_listener: Option<aos_sandbox_policy::native::RootCompletedPolicyListenerOriginalV1>,
    current_writers_receiving: Option<current_writers::RootCurrentWritersReceivingV1>,
    controller_peer_provision: Option<aos_sandbox_policy::native::RootControllerPeerProvisionOriginalV1>,
    controller_history_resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    current_open_provision: Option<current_open::RootCurrentOpenProvisionV1>,
    current_ready_provision: Option<current_ready::RootCurrentReadyProvisionV1>,
    current_pins_provision: Option<current_pins::RootCurrentPinsProvisionV1>,
    current_ownership_trust_provision: Option<current_ownership_trust::RootCurrentOwnershipTrustProvisionV1>,
    current_policy_inputs_provision: Option<current_provision::RootCurrentProvisionV1>,
    current_source_query_provision: Option<current_provision::RootCurrentProvisionV1>,
    current_source_exchange_provision: Option<current_provision::RootCurrentProvisionV1>,
    current_bundle_ownership_provision: Option<current_bundle_ownership::RootCurrentBundleOwnershipProvisionV1>,
    current_cache_proof_provision: Option<current_provision::RootCurrentProvisionV1>,
    current_controller_readonly_provision: Option<current_controller_readonly::RootCurrentControllerReadonlyProvisionV1>,
    current_use_authorized_provision: Option<current_provision::RootCurrentProvisionV1>,
    current_use_reserved_provision: Option<current_use_reserved::RootCurrentUseReservedProvisionV1>,
    current_closed_provision: Option<current_closed::RootClosedProvisionV1>,
    current_outcome_provision: Option<current_outcome::RootOutcomeProvisionV1>,
    current_signed_provision: Option<current_signed_bound::RootSignedProvisionV1>,
    current_use_admitted_provision: Option<current_provision::RootCurrentProvisionV1>,
}

impl RootReceivingOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            activation: aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1::new(
                Self::role_layout_v1(),
            ),
            native_receiving_refusal: None,
            service_observations: Default::default(),
            activation_names_refusal: None,
            role_error: None,
            original: None,
            shape: None,
            receiving_completion: None,
            recipient_binding: None,
            selected: None,
            selected_completion: None,
            service_currentness: None,
            native_startup_prior: None,
            native_completed_listener: None,
            current_writers_receiving: None,
            controller_peer_provision: None,
            controller_history_resident: None,
            current_open_provision: None,
            current_ready_provision: None,
            current_pins_provision: None,
            current_ownership_trust_provision: None,
            current_policy_inputs_provision: None,
            current_source_query_provision: None,
            current_source_exchange_provision: None,
            current_bundle_ownership_provision: None,
            current_cache_proof_provision: None,
            current_controller_readonly_provision: None,
            current_use_authorized_provision: None,
            current_use_reserved_provision: None,
            current_use_admitted_provision: None,
            current_signed_provision: None,
            current_outcome_provision: None, current_closed_provision: None,
        }
    }

    // The fixed table precedes even names parsing. All four returned OFDs are
    // parked before role selection; rejection keeps their actual owner/error.
    pub(crate) fn capture_once(&mut self) -> Result<(), ResourceReservationErrorV1> {
        let result = self.activation.capture_once();
        if self.activation.names_failure_v1().is_some() {
            self.activation_names_refusal.get_or_insert(crate::normal_root::NormalRootStartupErrorV1::Activation);
        }
        if self.activation.role_failure_v1().is_some() {
            self.role_error.get_or_insert(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        result.map_err(|cause| match cause {
            aos_sandbox_broker::receiving::RootInitialActivationErrorV1::Conflict => {
                ResourceReservationErrorV1::Conflict
            }
            _ => ResourceReservationErrorV1::EnrollmentUnavailable,
        })
    }

    pub(crate) fn authenticate_once(&mut self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.original.is_some() || !self.activation.is_captured_v1()
            || self.activation.process_id_v1() != std::process::id()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // The lower owner observes only its own fixed original files. Layout
        // DATA is supplied once by this private constructor, never as payment.
        let _ = self.activation.authenticate_once();
        self.original = Some(self.activation.enrollment_v1().copied()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable));
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.shape = Some(match self.activation.root_shape_result_v1() {
            Some(Ok(())) => Ok(()),
            // The unchanged Root-envelope law has only this coarse refusal.
            _ => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
        });
        if !matches!(self.shape, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        (original.policy.bootstrap_provisions().root_receiving)
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    // The original installed R covers its own negative prefix before the
    // recipient join. This one-way continuation can use only the profile from
    // that same first table; no vector, File or selected path pays this method.
    pub(crate) fn receive_profile_once(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if self.activation.process_id_v1() != std::process::id()
            || !matches!(self.shape, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let receiving = self.activation.receive_role_profile_once_v1();
        self.receiving_completion = self.activation.completion_result_v1()
            .map(|result| result.as_ref().map(|_| ()).map_err(|error| (*error).into()));
        self.recipient_binding = self.activation.recipient_binding_result_v1()
            .map(|result| result.as_ref().map(|_| ())
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable));
        receiving.map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.activation.table_failure_v1()
            .or_else(|| self.activation_names_refusal.as_ref()
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.activation.pair_failure_v1())
            .or_else(|| self.role_error.as_ref()
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.original.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.shape.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.activation.financial_failure_v1())
            .or_else(|| self.activation.role_profile_failure_v1())
            .or_else(|| self.activation.profile_capture_v1().and_then(|profile| profile.failure()))
            .or_else(|| self.activation.kernel_capture_v1().and_then(|kernel| kernel.failure()))
            .or_else(|| self.receiving_completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.recipient_binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.activation.role_selected_failure_v1())
            .or_else(|| self.activation.selected_admission_failure_v1())
            .or_else(|| self.selected.as_ref().and_then(|selected| selected.failure()))
            .or_else(|| self.selected_completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.service_observations.payment_failure())
            .or_else(|| self.native_startup_prior.as_ref().and_then(
                aos_sandbox_policy::native::RootStartupProvisionOriginalV1::failure_v1))
            .or_else(|| self.policy_flight_primary_failure_v1())
            .or_else(|| self.controller_peer_failure_v1())
            .or_else(|| self.current_writers_failure_v1())
            .or_else(|| self.current_open_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_ready_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_pins_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_policy_inputs_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_ownership_trust_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_source_query_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_source_exchange_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_bundle_ownership_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_cache_proof_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_controller_readonly_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_use_authorized_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_use_reserved_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_use_admitted_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_signed_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_closed_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.current_outcome_provision.as_ref().and_then(|stage| stage.failure()))
            .or_else(|| self.activation.currentness_failure_v1())
            .or_else(|| self.service_currentness.as_ref().and_then(|attempt| attempt.failure()))
            .or_else(|| self.native_receiving_refusal.as_ref()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)))
            .or_else(|| self.policy_flight_post_failure_v1())
            .or_else(|| self.activation.invocation_failure_v1())
    }
}

impl Drop for RootReceivingOriginalV1 {
    fn drop(&mut self) {
        self.activation.abort_if_root_armed_v1();
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn native_startup_prior_parts_mut_v1(
        &mut self,
    ) -> Result<(
        &mut aos_sandbox_policy::native::RootStartupProvisionOriginalV1,
        &mut aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1,
    ), crate::normal_root::NormalRootStartupErrorV1> {
        let prior = self.native_startup_prior.as_mut()
            .ok_or(crate::normal_root::NormalRootStartupErrorV1::Service)?;
        Ok((prior, &mut self.activation))
    }

    pub(crate) fn complete_native_listener_once_v1(
        &mut self,
    ) -> Result<(), crate::normal_root::NormalRootStartupErrorV1> {
        use crate::normal_root::NormalRootStartupErrorV1 as Error;
        if self.native_completed_listener.is_some() { self.activation.latch_root_refusal_v1(); return Err(Error::Service); }
        let prior = self.native_startup_prior.take().ok_or(Error::Service)?;
        match prior.complete_listener_into_original_v1(&self.activation) {
            Ok(original) => { self.native_completed_listener = Some(original); Ok(()) }
            Err(original) => {
                self.native_startup_prior = Some(original);
                self.activation.latch_root_refusal_v1();
                Err(Error::Service)
            }
        }
    }

    pub(crate) fn native_completed_listener_v1(
        &self,
    ) -> Result<aos_sandbox_policy::native::RootCompletedPolicyListenerOriginalV1,
        crate::normal_root::NormalRootStartupErrorV1> {
        self.native_completed_listener.as_ref().cloned()
            .ok_or(crate::normal_root::NormalRootStartupErrorV1::Service)
    }
}
