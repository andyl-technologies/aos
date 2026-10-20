//! Admits only this actual D flight's original challenge and bounded batch.
//!
//! The caller supplies its resident purpose owner, never an account or amount.
//! Its complete shape is derived before entropy, clocks or variable allocation.

mod source_predecessor;

use super::{ResourceReservationErrorV1, RootReceivingOriginalV1};
use crate::normal_root::NormalRootStartupErrorV1 as RootError;
use crate::policy_compiler::delete_root::{
    RootDeleteChallengeOriginalsV1, RootDeletePendingReceivingV1,
};
use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootPrearmedHistoryServicePostV1};

use aos_sandbox_core::component_receiving::{
    operation_traffic_demand_v1, without_operation_traffic_v1,
};

impl RootReceivingOriginalV1 {
    pub(crate) fn delete_exchange_financial_failure_v1(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_receiving_failure_v1()
            .or_else(|| self.failure())
    }

    pub(crate) fn admit_delete_opening_once_v1(
        &mut self,
        owner: &RootDeletePendingReceivingV1<'_, '_, '_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let demand = owner.opening_receiving_demand_v1()?;
            self.debit_observer_traffic_v1(operation_traffic_demand_v1(demand))
        })();
        if result.is_err() {
            self.activation.latch_root_refusal_v1();
        }
        result
    }

    pub(crate) fn admit_delete_challenge_once_v1(
        &mut self,
        owner: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let demand = owner.receiving_demand_v1()?;
            let base = self
                .policy_listener_prefix()
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let peer = crate::normal_root::RootDeleteControllerPeerReceivingV1::fixed_demand_v1()?;
            let complete = base
                .checked_add(without_operation_traffic_v1(peer))?
                .checked_add(without_operation_traffic_v1(demand))?;
            self.require_receiving_demand_v1(complete)?;
            self.debit_observer_traffic_v1(operation_traffic_demand_v1(demand))
        })();
        if result.is_err() {
            self.activation.latch_root_refusal_v1();
        }
        result
    }
}

/// Keeps both reached D chunk comparisons and all four actual Root posts.
///
/// An empty capsule has no authority. Only the same private Root receiving
/// original can arm it, after the complete D representation and traffic debit.
/// Keeps Delete's existing typed chunk-post surface on the shared engine.
pub(crate) type RootDeleteChunkPostsV1 = RootPurposeChunkPostsV1<super::DeleteRootPeerPurposeV1>;
/// Keeps Apply chunk posts bound to its distinct genuine opening and R loan.
pub(crate) type RootApplyChunkPostsV1 = RootPurposeChunkPostsV1<super::ApplyRootPeerPurposeV1>;
/// Keeps fresh Start resource posts on the same native mechanism and R.
pub(crate) type RootHostLaunchChunkPostsV2 = RootPurposeChunkPostsV1<super::HostLaunchRootPeerPurposeV1>;
/// Binds Maintenance chunks to their actual distinct current R purpose.
pub(crate) type RootMaintenanceStorageChunkPostsV2 = RootPurposeChunkPostsV1<super::MaintenanceStorageRootPeerPurposeV2>;
/// Binds Execution chunks to their same paid Root purpose.
pub(crate) type RootExecutionNoApplyChunkPostsV2 = RootPurposeChunkPostsV1<super::ExecutionNoApplyRootPeerPurposeV2>;
/// Binds Stop cleanup chunks to the same actual current Root purpose.
pub(crate) type RootStopCleanupChunkPostsV1 = RootPurposeChunkPostsV1<super::StopCleanupRootPeerPurposeV1>;
/// Binds read-only Start input chunks to their actual same-R native purpose.
pub(crate) type RootStartAssignmentInputsChunkPostsV2 = RootPurposeChunkPostsV1<super::StartAssignmentInputsRootPeerPurposeV2>;

// The two concrete owner references select only a closed native schedule.
// Neither comparison data nor a caller flag can construct either original.
enum ChunkOwnerV1<'owner> {
    ExecutionNoApply(&'owner crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyOpeningOriginalV2),
    StopCleanup(&'owner crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupOpeningOriginalV1),
    Planning(&'owner crate::policy_compiler::delete_root::RootDeletePlanningChallengeOriginalV1),
    Delete(&'owner RootDeleteChallengeOriginalsV1),
    Apply(&'owner crate::policy_compiler::storage_apply_root::RootStorageApplyOpeningOriginalV1),
    StartInputs(&'owner crate::policy_compiler::start_assignment_inputs_root::opening::RootStartAssignmentInputsOpeningOriginalV2),
    Host(&'owner crate::policy_compiler::host_launch_root::RootHostLaunchOpeningOriginalV2),
    MaintenanceStorage(&'owner crate::policy_compiler::host_launch_root::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2),
}

impl ChunkOwnerV1<'_> {
    fn require_paid_peak_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::ExecutionNoApply(owner) => owner.require_paid_chunk_peak_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict),
            Self::StopCleanup(owner) => owner.require_paid_chunk_peak_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict),
            Self::Delete(owner) => owner.require_paid_chunk_peak_v1(),
            Self::Planning(owner) => owner.require_paid_chunk_peak_v1(),
            Self::Apply(owner) => owner.require_paid_chunk_peak_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict),
            Self::Host(owner) => owner.require_paid_chunk_peak_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict),
            Self::MaintenanceStorage(owner) => owner.require_paid_chunk_peak_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict),
            Self::StartInputs(owner) => owner.require_paid_chunk_peak_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict),
        }
    }

    fn observe_post_v1(&self, flight: &crate::normal_root::RootPolicyAcceptedFlightV1<'_, '_>,
        post: &mut crate::normal_root::RootHistoryPeerPostV1,
    ) -> Result<(), RootError> {
        match self {
            Self::ExecutionNoApply(owner) => flight.observe_execution_no_apply_chunk_post_once_v2(post, owner),
            Self::StopCleanup(owner) => flight.observe_stop_cleanup_chunk_post_once_v1(post, owner),
            Self::Delete(owner) => flight.observe_delete_chunk_post_once_v1(post, owner),
            Self::Planning(owner) => flight.observe_delete_planning_chunk_post_once_v1(post, owner),
            Self::Apply(owner) => flight.observe_apply_chunk_post_once_v1(post, owner),
            Self::Host(owner) => flight.observe_host_launch_chunk_post_once_v2(post, owner),
            Self::MaintenanceStorage(owner) => flight.observe_maintenance_storage_chunk_post_once_v2(post, owner),
            Self::StartInputs(owner) => flight.observe_start_assignment_inputs_chunk_post_once_v2(post, owner),
        }
    }
}

#[derive(Default)]
pub(crate) struct RootPurposeChunkPostsV1<K: super::RootPeerPurposeV1> {
    purpose: std::marker::PhantomData<K>,
    entered: bool,
    permit: Option<Result<(), ResourceReservationErrorV1>>,
    before_arms: [Option<Result<RootPrearmedHistoryServicePostV1, RootObservationErrorV1>>; 2],
    after_arms: [Option<Result<RootPrearmedHistoryServicePostV1, RootObservationErrorV1>>; 2],
    arm_posts: [Option<Result<(), RootError>>; 4],
    before: Option<crate::normal_root::RootHistoryPeerPostV1>,
    before_result: Option<Result<(), RootError>>,
    after: Option<crate::normal_root::RootHistoryPeerPostV1>,
    after_result: Option<Result<(), RootError>>,
    closed: Option<RootError>,
}

impl<K: super::RootPeerPurposeV1> RootPurposeChunkPostsV1<K> {
    pub(crate) fn fixed_demand_v1()
    -> Result<aos_sandbox_core::ResourceVector, ResourceReservationErrorV1> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let post = crate::normal_root::RootHistoryPeerPostV1::demand_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        // These are distinct paid worker bounds, not InitialController's
        // shared worker lane. Negative native/runtime prefixes stay resident.
        post.checked_add(post)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(Into::into)
    }

    pub(crate) fn traffic_demand_v1()
    -> Result<aos_sandbox_core::ResourceVector, ResourceReservationErrorV1> {
        let traffic = crate::normal_root::RootHistoryPeerPostV1::traffic_demand_v1()?;
        traffic.checked_add(traffic).map_err(Into::into)
    }

    pub(crate) fn require_armed_v1(&self) -> Result<(), RootError> {
        if matches!(self.permit, Some(Ok(())))
            && self.before.is_some()
            && self.after.is_some()
            && self.closed.is_none()
        {
            Ok(())
        } else {
            Err(RootError::Service)
        }
    }

    fn observe_before_inner_v1(
        &mut self,
        flight: &crate::normal_root::RootPolicyAcceptedFlightV1<'_, '_>,
        owner: ChunkOwnerV1<'_>,
    ) -> Result<(), RootError> {
        self.require_armed_v1()?;
        if self.before_result.is_some() {
            self.closed.get_or_insert(RootError::Service);
            return Err(RootError::Service);
        }
        self.before_result = Some(match self.before.as_mut() {
            Some(post) => owner.observe_post_v1(flight, post),
            None => Err(RootError::Service),
        });
        if matches!(self.before_result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootError::Service)
        }
    }

    fn observe_after_inner_v1(
        &mut self,
        flight: &crate::normal_root::RootPolicyAcceptedFlightV1<'_, '_>,
        owner: ChunkOwnerV1<'_>,
    ) -> Result<(), RootError> {
        // An earlier before/parser/native error cannot suppress this armed
        // independent debt. This does not consult the capsule's healthy view.
        if self.after_result.is_some() {
            self.closed.get_or_insert(RootError::Service);
            return Err(RootError::Service);
        }
        self.after_result = Some(match self.after.as_mut() {
            Some(post) => owner.observe_post_v1(flight, post),
            None => Err(RootError::Service),
        });
        if matches!(self.after_result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootError::Service)
        }
    }

    pub(crate) fn require_positive_v1(&self) -> Result<(), RootError> {
        self.require_armed_v1()?;
        if matches!(self.before_result, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(())))
            && self
                .before
                .as_ref()
                .is_some_and(|post| post.is_positive_v1())
            && self
                .after
                .as_ref()
                .is_some_and(|post| post.is_positive_v1())
            && self.failure().is_none()
        {
            Ok(())
        } else {
            Err(RootError::Service)
        }
    }

    pub(crate) fn funding_failed_v1(&self) -> bool {
        matches!(self.permit, Some(Err(_)))
    }

    pub(crate) fn before_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.permit
            .as_ref()
            .and_then(|permit| permit.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.before_arms
                    .iter()
                    .chain(&self.after_arms)
                    .find_map(|arm| arm.as_ref()?.as_ref().err().map(|cause| cause as _))
            })
            .or_else(|| self.before.as_ref().and_then(|post| post.failure()))
            .or_else(|| {
                self.before_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }

    pub(crate) fn after_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.after
            .as_ref()
            .and_then(|post| post.failure())
            .or_else(|| {
                self.after_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn property_failure_view_v1(
        &self,
        first: &(dyn std::error::Error + 'static),
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        for post in [&self.before, &self.after].into_iter().flatten() {
            if post
                .failure()
                .is_some_and(|cause| std::ptr::addr_eq(first as *const _, cause as *const _))
            {
                return post.property_failure_view_v1();
            }
        }
        None
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(
            value: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        cause(&self.permit)
            .or_else(|| {
                self.before_arms
                    .iter()
                    .chain(&self.after_arms)
                    .find_map(|arm| cause(arm))
            })
            .or_else(|| self.arm_posts.iter().find_map(|post| cause(post)))
            .or_else(|| self.before.as_ref().and_then(|post| post.failure()))
            .or_else(|| cause(&self.before_result))
            .or_else(|| self.after.as_ref().and_then(|post| post.failure()))
            .or_else(|| cause(&self.after_result))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

// Named wrappers retain distinct static purpose types and concrete owners.
macro_rules! chunk_observation_ports {
    ($purpose:ty, $owner:ty, $variant:ident) => {
        impl RootPurposeChunkPostsV1<$purpose> {
            pub(crate) fn observe_before_once_v1(&mut self,
                flight: &crate::normal_root::RootPolicyAcceptedFlightV1<'_, '_>, owner: &$owner,
            ) -> Result<(), RootError> {
                self.observe_before_inner_v1(flight, ChunkOwnerV1::$variant(owner))
            }

            pub(crate) fn observe_after_once_v1(&mut self,
                flight: &crate::normal_root::RootPolicyAcceptedFlightV1<'_, '_>, owner: &$owner,
            ) -> Result<(), RootError> {
                self.observe_after_inner_v1(flight, ChunkOwnerV1::$variant(owner))
            }
        }
    };
}

chunk_observation_ports!(super::ExecutionNoApplyRootPeerPurposeV2, crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyOpeningOriginalV2, ExecutionNoApply);
chunk_observation_ports!(super::StopCleanupRootPeerPurposeV1, crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupOpeningOriginalV1, StopCleanup);
chunk_observation_ports!(super::DeleteRootPeerPurposeV1, RootDeleteChallengeOriginalsV1, Delete);
chunk_observation_ports!(super::ApplyRootPeerPurposeV1,
    crate::policy_compiler::storage_apply_root::RootStorageApplyOpeningOriginalV1, Apply);
chunk_observation_ports!(super::HostLaunchRootPeerPurposeV1,
    crate::policy_compiler::host_launch_root::RootHostLaunchOpeningOriginalV2, Host);
chunk_observation_ports!(super::MaintenanceStorageRootPeerPurposeV2,
    crate::policy_compiler::host_launch_root::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2, MaintenanceStorage);

impl RootReceivingOriginalV1 {
    pub(crate) fn arm_delete_chunk_posts_once_v1(
        &mut self, startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: &RootDeleteChallengeOriginalsV1, posts: &mut RootDeleteChunkPostsV1,
    ) -> Result<(), RootError> {
        self.arm_purpose_chunk_posts_inner_v1(startup, ChunkOwnerV1::Delete(owner), posts)
    }

    pub(crate) fn arm_apply_chunk_posts_once_v1(
        &mut self, startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: &crate::policy_compiler::storage_apply_root::RootStorageApplyOpeningOriginalV1,
        posts: &mut RootApplyChunkPostsV1,
    ) -> Result<(), RootError> {
        self.arm_purpose_chunk_posts_inner_v1(startup, ChunkOwnerV1::Apply(owner), posts)
    }

    pub(crate) fn arm_host_launch_chunk_posts_once_v2(
        &mut self, startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: &crate::policy_compiler::host_launch_root::RootHostLaunchOpeningOriginalV2,
        posts: &mut RootHostLaunchChunkPostsV2,
    ) -> Result<(), RootError> {
        self.arm_purpose_chunk_posts_inner_v1(startup, ChunkOwnerV1::Host(owner), posts)
    }

    pub(crate) fn arm_maintenance_storage_chunk_posts_once_v2(
        &mut self, startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: &crate::policy_compiler::host_launch_root::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2,
        posts: &mut RootMaintenanceStorageChunkPostsV2,
    ) -> Result<(), RootError> {
        self.arm_purpose_chunk_posts_inner_v1(startup, ChunkOwnerV1::MaintenanceStorage(owner), posts)
    }

    pub(crate) fn arm_execution_no_apply_chunk_posts_once_v2(
        &mut self, startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: &crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyOpeningOriginalV2, posts: &mut RootExecutionNoApplyChunkPostsV2,
    ) -> Result<(), RootError> {
        self.arm_purpose_chunk_posts_inner_v1(startup, ChunkOwnerV1::ExecutionNoApply(owner), posts)
    }

    pub(crate) fn arm_stop_cleanup_chunk_posts_once_v1(
        &mut self, startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: &crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupOpeningOriginalV1, posts: &mut RootStopCleanupChunkPostsV1,
    ) -> Result<(), RootError> {
        self.arm_purpose_chunk_posts_inner_v1(startup, ChunkOwnerV1::StopCleanup(owner), posts)
    }

    fn arm_purpose_chunk_posts_inner_v1<K: super::RootPeerPurposeV1>(
        &mut self,
        startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: ChunkOwnerV1<'_>,
        posts: &mut RootPurposeChunkPostsV1<K>,
    ) -> Result<(), RootError> {
        use super::super::service_interval::ObserverLifetime;
        use crate::normal_root::{NormalRootStartupErrorV1 as Error, RootHistoryPeerPostV1};
        if posts.entered {
            posts.closed.get_or_insert(Error::Service);
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        posts.entered = true;
        let returned = (|| {
            self.require_active_policy_flight_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            // The actual same D challenge already prepaid the complete single
            // resident chunk peak. Only reached consumable traffic grows here.
            owner.require_paid_peak_v1()?;
            self.debit_observer_traffic_v1(RootPurposeChunkPostsV1::<K>::traffic_demand_v1()?)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(&mut posts.permit, returned);
        if !matches!(posts.permit, Some(Ok(()))) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        // Park every actual arm result independently before projecting any
        // refusal. Earlier armed originals remain here after a later failure.
        for arm in posts.before_arms.iter_mut().chain(&mut posts.after_arms) {
            let returned = self.activation
                .arm_history_service_post_v1(startup.native_startup_original_v1());
            self.native_refusal_original_v1().park_empty_result_v1(arm, returned);
        }
        if posts
            .before_arms
            .iter()
            .chain(&posts.after_arms)
            .any(|arm| !matches!(arm, Some(Ok(_))))
        {
            // A later arm refusal must not suppress the earlier actual owed
            // destinations. Observe every successfully armed native original
            // before projecting the retained arm failure; keep all results.
            for (index, arm) in posts
                .before_arms
                .iter_mut()
                .chain(&mut posts.after_arms)
                .enumerate()
            {
                if let Some(Ok(arm)) = arm.as_mut() {
                    let returned = self.activation.observe_history_service_post_once_v1(
                        startup.native_startup_original_v1(), arm,
                    ).map_err(Into::into);
                    self.native_refusal_original_v1().park_empty_result_v1(
                        &mut posts.arm_posts[index], returned,
                    );
                }
            }
            return Err(Error::Service);
        }
        let (Some(Ok(before0)), Some(Ok(before1)), Some(Ok(after0)), Some(Ok(after1))) = (
            posts.before_arms[0].take(),
            posts.before_arms[1].take(),
            posts.after_arms[0].take(),
            posts.after_arms[1].take(),
        ) else {
            std::process::abort();
        };
        posts.before = Some(RootHistoryPeerPostV1::from_originals_v1(
            before0,
            before1,
            ObserverLifetime::begin(),
            Ok(()),
        ));
        posts.after = Some(RootHistoryPeerPostV1::from_originals_v1(
            after0,
            after1,
            ObserverLifetime::begin(),
            Ok(()),
        ));
        posts.require_armed_v1()
    }
}


impl RootReceivingOriginalV1 {
    pub(crate) fn admit_delete_controller_current_v1(&mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        owner: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let entered = owner.receiving_demand_v1()?;
            let previous = challenge.retained_receiving_demand_v1()?;
            let base = self.policy_listener_prefix().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let peer = crate::normal_root::RootDeleteControllerPeerReceivingV1::fixed_demand_v1()?;
            let complete = base.checked_add(without_operation_traffic_v1(peer))?
                .checked_add(without_operation_traffic_v1(previous))?
                .checked_add(without_operation_traffic_v1(entered))?;
            self.require_receiving_demand_v1(complete)?;
            self.debit_observer_traffic_v1(operation_traffic_demand_v1(entered))
        })();
        if result.is_err() { self.activation.latch_root_refusal_v1(); }
        result
    }
}


impl RootReceivingOriginalV1 {
    pub(crate) fn require_delete_controller_funding_original_v3(&self,
        owner: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_delete_funding_enrollment_v3(owner.controller_funding_v3()?)
    }
}

impl RootDeleteChunkPostsV1 {
    pub(crate) fn observe_planning_before_once_v1(&mut self,
        flight: &crate::normal_root::RootPolicyAcceptedFlightV1<'_, '_>,
        owner: &crate::policy_compiler::delete_root::RootDeletePlanningChallengeOriginalV1,
    ) -> Result<(), RootError> {
        self.observe_before_inner_v1(flight, ChunkOwnerV1::Planning(owner))
    }

    pub(crate) fn observe_planning_after_once_v1(&mut self,
        flight: &crate::normal_root::RootPolicyAcceptedFlightV1<'_, '_>,
        owner: &crate::policy_compiler::delete_root::RootDeletePlanningChallengeOriginalV1,
    ) -> Result<(), RootError> {
        self.observe_after_inner_v1(flight, ChunkOwnerV1::Planning(owner))
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn arm_delete_planning_chunk_posts_once_v1(&mut self,
        startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: &crate::policy_compiler::delete_root::RootDeletePlanningChallengeOriginalV1,
        posts: &mut RootDeleteChunkPostsV1,
    ) -> Result<(), RootError> {
        self.arm_purpose_chunk_posts_inner_v1(startup, ChunkOwnerV1::Planning(owner), posts)
    }
}

impl RootReceivingOriginalV1 {
    fn require_delete_funding_enrollment_v3(&self,
        funding: &aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1,
    ) -> Result<(),ResourceReservationErrorV1> {
        self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let original = self.original.as_ref().and_then(|original| original.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if funding.enrollment_v1() != original.identity { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }

    pub(crate) fn require_delete_planning_funding_original_v3(&self,
        owner: &crate::policy_compiler::delete_root::RootDeletePlanningDispatchOriginalV1,
    ) -> Result<(),ResourceReservationErrorV1> {
        self.require_delete_funding_enrollment_v3(owner.planning_funding_v3()?)
    }

    pub(crate) fn admit_delete_planning_opening_once_v1(&mut self,
        owner: &crate::policy_compiler::delete_root::RootDeletePlanningDispatchOriginalV1,
    ) -> Result<(),ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.debit_observer_traffic_v1(operation_traffic_demand_v1(owner.opening_receiving_demand_v1()?))
        })();
        if result.is_err() { self.activation.latch_root_refusal_v1(); }
        result
    }

    pub(crate) fn admit_delete_planning_challenge_once_v1(&mut self,
        owner: &crate::policy_compiler::delete_root::RootDeletePlanningChallengeOriginalV1,
    ) -> Result<(),ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let entered = owner.receiving_demand_v1()?;
            let base = self.policy_listener_prefix().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let peer = crate::normal_root::RootDeleteControllerPeerReceivingV1::fixed_demand_v1()?;
            let complete = base.checked_add(without_operation_traffic_v1(peer))?
                .checked_add(without_operation_traffic_v1(entered))?;
            self.require_receiving_demand_v1(complete)?;
            self.debit_observer_traffic_v1(operation_traffic_demand_v1(entered))
        })();
        if result.is_err() { self.activation.latch_root_refusal_v1(); }
        result
    }

    pub(crate) fn admit_delete_planning_read_once_v1(&mut self,
        owner: &crate::policy_compiler::delete_root::RootDeletePlanningDispatchOriginalV1,
    ) -> Result<(),ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let entered = owner.receiving_demand_v1()?;
            let base = self.policy_listener_prefix().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let peer = crate::normal_root::RootDeleteControllerPeerReceivingV1::fixed_demand_v1()?;
            let complete = base.checked_add(without_operation_traffic_v1(peer))?
                .checked_add(without_operation_traffic_v1(entered))?;
            self.require_receiving_demand_v1(complete)
        })();
        if result.is_err() { self.activation.latch_root_refusal_v1(); }
        result
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn admit_delete_source_current_v1(&mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let entered = source.receiving_demand_v1()?;
            let previous = challenge.retained_receiving_demand_v1()?;
            let controller = controller.retained_receiving_demand_v1()?;
            let base = self.policy_listener_prefix().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let peer = crate::normal_root::RootDeleteControllerPeerReceivingV1::fixed_demand_v1()?;
            let complete = base.checked_add(without_operation_traffic_v1(peer))?
                .checked_add(without_operation_traffic_v1(previous))?
                .checked_add(without_operation_traffic_v1(controller))?
                .checked_add(without_operation_traffic_v1(entered))?;
            self.require_receiving_demand_v1(complete)?;
            self.debit_observer_traffic_v1(operation_traffic_demand_v1(entered))
        })();
        if result.is_err() { self.activation.latch_root_refusal_v1(); }
        result
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn admit_delete_floor_v1(&mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
        floor: &crate::policy_compiler::delete_root::RootDeleteFloorOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let entered = floor.receiving_demand_v1()?;
            let previous = challenge.retained_receiving_demand_v1()?;
            let controller = controller.retained_receiving_demand_v1()?;
            let source = source.retained_receiving_demand_v1()?;
            let base = self.policy_listener_prefix().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let peer = crate::normal_root::RootDeleteControllerPeerReceivingV1::fixed_demand_v1()?;
            let complete = base.checked_add(without_operation_traffic_v1(peer))?
                .checked_add(without_operation_traffic_v1(previous))?
                .checked_add(without_operation_traffic_v1(controller))?
                .checked_add(without_operation_traffic_v1(source))?
                .checked_add(without_operation_traffic_v1(entered))?;
            self.require_receiving_demand_v1(complete)
        })();
        if result.is_err() { self.activation.latch_root_refusal_v1(); }
        result
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn admit_delete_transfer_namespace_v1(&mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
        floor: &crate::policy_compiler::delete_root::RootDeleteFloorOriginalV1,
        namespace: &crate::policy_compiler::delete_root::RootDeleteTransferNamespaceOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let entered = namespace.receiving_demand_v1()?;
            let previous = challenge.retained_receiving_demand_v1()?;
            let controller = controller.retained_receiving_demand_v1()?;
            let source = source.retained_receiving_demand_v1()?;
            let floor = floor.retained_receiving_demand_v1()?;
            let base = self.policy_listener_prefix().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let peer = crate::normal_root::RootDeleteControllerPeerReceivingV1::fixed_demand_v1()?;
            let complete = base.checked_add(without_operation_traffic_v1(peer))?
                .checked_add(without_operation_traffic_v1(previous))?
                .checked_add(without_operation_traffic_v1(controller))?
                .checked_add(without_operation_traffic_v1(source))?
                .checked_add(without_operation_traffic_v1(floor))?
                .checked_add(without_operation_traffic_v1(entered))?;
            self.require_receiving_demand_v1(complete)?;
            self.debit_observer_traffic_v1(operation_traffic_demand_v1(entered))
        })();
        if result.is_err() { self.activation.latch_root_refusal_v1(); }
        result
    }
}

chunk_observation_ports!(super::StartAssignmentInputsRootPeerPurposeV2,
    crate::policy_compiler::start_assignment_inputs_root::opening::RootStartAssignmentInputsOpeningOriginalV2,
    StartInputs);

impl RootReceivingOriginalV1 {
    pub(crate) fn arm_start_assignment_inputs_chunk_posts_once_v2(
        &mut self,
        startup: &crate::normal_root::ProductionNormalRootStartupV1,
        owner: &crate::policy_compiler::start_assignment_inputs_root::opening::RootStartAssignmentInputsOpeningOriginalV2,
        posts: &mut RootStartAssignmentInputsChunkPostsV2,
    ) -> Result<(), RootError> {
        self.arm_purpose_chunk_posts_inner_v1(startup, ChunkOwnerV1::StartInputs(owner), posts)
    }
}
