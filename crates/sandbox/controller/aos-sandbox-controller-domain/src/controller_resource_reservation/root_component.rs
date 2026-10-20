//! Retains the original Root subdivision of the already-paid Components grant.
//!
//! R is one permanent purpose-13 claim, not a Root account or operation loan.
//! PID1 installs its whole-service bounds before exec, including the negative
//! prefix that authenticates these original image and delivery descriptors.
//! Native DATA never reconstructs that producer or refunds a dead invocation.

mod selected_startup;
mod service_observation;
mod root_journal;
mod credential_receiving;
mod current_writers;
mod policy_listener;
mod controller_peer;
mod delete_peer;
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
    profile_prefix: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    receiving_completion: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    recipient_binding: Option<Result<(), ResourceReservationErrorV1>>,
    selected_prefix: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    selected: Option<crate::normal_root::RootSelectedStartupReceivingV1>,
    selected_completion: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    service_currentness: Option<crate::normal_root::RootServiceCurrentnessV1>,
    journal_receiving: Option<root_journal::RootJournalReceivingV1>,
    credential_receiving: Option<credential_receiving::RootCredentialReceivingV1>,
    current_writers_receiving: Option<current_writers::RootCurrentWritersReceivingV1>,
    policy_listener_provision: Option<policy_listener::RootPolicyListenerProvisionV1>,
    controller_peer_provision: Option<controller_peer::RootControllerPeerProvisionV1>,
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
                crate::controller_resource_reservation::q04_intake::native_layout(),
            ),
            native_receiving_refusal: None,
            service_observations: Default::default(),
            activation_names_refusal: None,
            role_error: None,
            original: None,
            shape: None,
            profile_prefix: None,
            receiving_completion: None,
            recipient_binding: None,
            selected_prefix: None,
            selected: None,
            selected_completion: None,
            service_currentness: None,
            journal_receiving: None,
            credential_receiving: None,
            current_writers_receiving: None,
            policy_listener_provision: None,
            controller_peer_provision: None,
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
        if self.profile_prefix.is_some()
            || self.activation.process_id_v1() != std::process::id()
            || !matches!(self.shape, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let returned = (|| {
            let envelope = self.original.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let native = aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1::
                fixed_profile_prefix_demand_v1()
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            // The lower lane pays only its actual native owners. This private
            // role separately pays its retained classification and constructor
            // carriers, with no DATA supplied by an external caller.
            let error_arc = std::mem::size_of::<ResourceReservationErrorV1>()
                .checked_add(2 * std::mem::size_of::<usize>())
                .and_then(|bytes| bytes.checked_add(std::mem::align_of::<ResourceReservationErrorV1>() - 1))
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let adapter_bytes = std::mem::size_of::<Self>().checked_mul(2)
                // Heap backing and its actual construction carrier coexist
                // on the one failed debit. Later views clone only Arc pointers.
                .and_then(|bytes| bytes.checked_add(error_arc.checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<crate::normal_root::NormalRootStartupErrorV1>,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
                    usize, usize, std::sync::Mutex<()>,
                )>()))
                .and_then(|bytes| bytes.checked_add(
                    std::mem::size_of::<ResourceVector>().checked_mul(5)?,
                ))
                // Actual Root67 nested construction carriers: OwnershipTrust
                // container and fixed/typed/SourceExchange provisions. Their
                // stored destinations are already in actual Self above.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_ownership_trust::RootCurrentOwnershipTrustProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >().checked_mul(3)?))
                // BundleOwnership's private container/fixed/typed constructor
                // carriers exist before their own later admission can succeed.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_bundle_ownership::RootCurrentBundleOwnershipProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >().checked_mul(2)?))
                // These two actual RootAttempt headers are constructed at new,
                // before BundleOwnership admission. State/child Box allocations
                // remain in their own later fixed/typed suppliers.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::bundle_ownership::
                        RootCurrentBundleOwnershipStateV1,
                >>>()))
                // CacheCurrent adds its own provision constructor and two
                // RootAttempt headers at new, before its later fixed gate.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::cache_current::
                        RootCurrentCacheProofStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<
                    (), aos_sandbox_broker::receiving::RootObservationErrorV1,
                >>()))
                // The readonly stage container and its three provision
                // constructors precede their own later successful gates.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_controller_readonly::RootCurrentControllerReadonlyProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >().checked_mul(3)?))
                // The two headers are initialized with the actual RootAttempt.
                // Its State Box/backing remains a later fixed-stage cost.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::controller_readonly::
                        RootCurrentControllerReadonlyStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
                >()))
                // The new Box header is present from initial attempt creation;
                // its backing and construction are admitted only at UA entry.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::use_authorized::
                        RootCurrentUseAuthorizedStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::use_reserved::RootCurrentUseReservedStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Result<
                    (), crate::normal_root::NormalRootStartupErrorV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_use_reserved::RootCurrentUseReservedProvisionV1,
                >()))
                // Fresh Source query/exchange are distinct inline originals;
                // their native reservoirs remain paid at their own R stages.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceQueryStateV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceExchangeStateV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::cache_current::RootCurrentCacheProofStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Result<
                    (), crate::normal_root::NormalRootStartupErrorV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<current_provision::RootCurrentProvisionV1>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Result<
                    (), crate::normal_root::NormalRootStartupErrorV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<current_signed_bound::RootSignedProvisionV1>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1>>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>>()))
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let adapter = ResourceVector::ZERO
                .with(aos_sandbox_model::ResourceDimension::MemoryBytes,
                    u64::try_from(adapter_bytes).map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?)
                // Four financial fields move to the actual lower original;
                // the historical parent subtotal therefore falls from27 to23.
                // Keep the existing additional parent/nested controls below.
                // Arc/Mutex/startup and financial carriers, eight older nested
                // controls and four older constructors. BundleOwnership adds
                // six nested fixed/typed destination+Result controls and three
                // constructors; its two RootAttempt headers are also upfront.
                // CacheCurrent adds its parent above plus two embedded Results,
                // one constructor and two RootAttempt headers. The independent
                // retained RootChunk clock header from 81b3 remains upfront;
                // its physical bytes are already in listener sizeof(RootAttempt).
                // The armed header moved to the native original. The actual
                // checked handoff Result now owns one explicit cell and sizeof
                // above. ControllerReadonly adds its parent field, three
                // embedded stage destinations and six permit/before Results,
                // four constructor carriers and two early RootAttempt headers:
                // sixteen cells beyond the existing65, for actual upfront81.
                // Native initial's69 cells remain separately paid; later State
                // backing/model/native/semantic stages retain their own gates.
                .with(aos_sandbox_model::ResourceDimension::MetadataEntries,
                    (27 - 4) + 1 + 3 + 5 + 8 + 4 + 6 + 3 + 2 + 2 + 1 + 2 + 1 + 1 + 9 + 4 + 2);
            let guards = crate::normal_root::RootReceivingGuardV1::construction_demand_v1()
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let demand = native.checked_add(adapter)
                .and_then(|demand| demand.checked_add(guards))
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            envelope.checked_sub(demand).map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            self.activation.require_receiving_demand_v1(demand)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(&mut self.profile_prefix, returned);
        if !matches!(self.profile_prefix, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }

        let receiving = self.activation.receive_profile_once();
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
            .or_else(|| self.profile_prefix.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.activation.profile_capture_v1().and_then(|profile| profile.failure()))
            .or_else(|| self.activation.kernel_capture_v1().and_then(|kernel| kernel.failure()))
            .or_else(|| self.receiving_completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.recipient_binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.selected_prefix.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.activation.selected_admission_failure_v1())
            .or_else(|| self.selected.as_ref().and_then(|selected| selected.failure()))
            .or_else(|| self.selected_completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.service_observations.payment_failure())
            .or_else(|| self.journal_failure())
            .or_else(|| self.credential_failure())
            .or_else(|| self.policy_listener_provision.as_ref().and_then(|stage| stage.failure()))
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
