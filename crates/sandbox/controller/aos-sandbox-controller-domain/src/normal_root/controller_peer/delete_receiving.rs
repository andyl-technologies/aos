//! Retains a purpose-bound flight's Controller peer and all Root service debts.
//!
//! The same existing native/PID1 capture and current-sample engines perform the
//! observations. This owner has separate once-only destinations on this actual
//! accepted flight; it cannot reuse InitialController or establish Delete,
//! Source, six-owner, publication or terminal authority from comparison DATA.

mod stages;

pub(crate) use stages::{RootStopCleanupStageReceivingV1, RootMaintenanceStorageStageReceivingV2, RootDeleteCacheStageReceivingV2, RootApplyStageReceivingV1, RootHostLaunchStageReceivingV1, RootEnvironmentStageReceivingV1, RootFinalityRecoverStageReceivingV1, RootStartAssignmentInputsStageReceivingV2};

use std::error::Error as StdError;

use aos_sandbox_broker::receiving::{RootPrearmedHistoryServicePostV1, RootPurposePeerPostsOriginalV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

use super::receiving::{RootControllerPeerCurrentSampleV1, RootControllerPeerReceivingV1};
use super::{Error, ProductionNormalRootStartupV1};
use crate::controller_resource_reservation::{
    ResourceReservationErrorV1, RootPurposePeerAdmissionV1, RootPurposePeerPostV1,
    RootPeerPurposeV1, StopCleanupRootPeerPurposeV1, DeleteRootPeerPurposeV1, EnvironmentRootPeerPurposeV1,
    ApplyRootPeerPurposeV1, HostLaunchRootPeerPurposeV1, MaintenanceStorageRootPeerPurposeV2, FinalityRecoverRootPeerPurposeV1,
    service_interval::ObserverLifetime,
};

/// Keeps the existing Delete ports bound to their distinct native destination.
pub(crate) type RootDeleteControllerPeerReceivingV1<'startup> =
    RootPurposeControllerPeerReceivingV1<'startup, DeleteRootPeerPurposeV1>;

/// Binds the Environment native destination without issuing an Environment claim.
pub(crate) type RootEnvironmentControllerPeerReceivingV1<'startup> =
    RootPurposeControllerPeerReceivingV1<'startup, EnvironmentRootPeerPurposeV1>;

/// Binds a fresh Apply native destination without accepting an Apply outcome.
pub(crate) type RootApplyControllerPeerReceivingV1<'startup> =
    RootPurposeControllerPeerReceivingV1<'startup, ApplyRootPeerPurposeV1>;

/// Binds the fresh Stop cleanup peer without adopting an old Stop owner.
pub(crate) type RootStopCleanupControllerPeerReceivingV1<'startup> =
    RootPurposeControllerPeerReceivingV1<'startup, StopCleanupRootPeerPurposeV1>;

/// Binds a fresh Host-launch native destination without granting a launch.
pub(crate) type RootHostLaunchControllerPeerReceivingV1<'startup> =
    RootPurposeControllerPeerReceivingV1<'startup, HostLaunchRootPeerPurposeV1>;

/// Binds a new Recover observation peer without authorizing an old effect.
pub(crate) type RootFinalityRecoverControllerPeerReceivingV1<'startup> =
    RootPurposeControllerPeerReceivingV1<'startup, FinalityRecoverRootPeerPurposeV1>;

/// Binds only current Maintenance Storage31 to its own actual Root peer.
pub(crate) type RootMaintenanceStorageControllerPeerReceivingV2<'startup> =
    RootPurposeControllerPeerReceivingV1<'startup, MaintenanceStorageRootPeerPurposeV2>;

pub(crate) struct RootPurposeControllerPeerReceivingV1<'startup, K: RootPeerPurposeV1> {
    startup: &'startup ProductionNormalRootStartupV1,
    admission: RootPurposePeerAdmissionV1<K>,
    funding: Option<Result<(), Error>>,
    posts: [Option<Result<(), Error>>; 4],
    peer: Option<RootControllerPeerReceivingV1<'startup>>,
    capture: Option<Result<(), Error>>,
    initial_settlement: Option<Result<(), Error>>,
    current: Option<RootControllerPeerCurrentSampleV1>,
    current_result: Option<Result<(), Error>>,
    final_settlement: Option<Result<(), Error>>,
    entered: bool,
    final_entered: bool,
    complete: bool,
    closed: Option<Error>,
}

impl<'startup, K: RootPeerPurposeV1> RootPurposeControllerPeerReceivingV1<'startup, K> {
    pub(in crate::normal_root) fn new(startup: &'startup ProductionNormalRootStartupV1) -> Self {
        Self {
            startup,
            admission: Default::default(),
            funding: None,
            posts: [None, None, None, None],
            peer: None,
            capture: None,
            initial_settlement: None,
            current: None,
            current_result: None,
            final_settlement: None,
            entered: false,
            final_entered: false,
            complete: false,
            closed: None,
        }
    }

    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let post = RootPrearmedHistoryServicePostV1::demand_v1().ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(RootPurposePeerPostsOriginalV1::<Error>::operation_control_bytes_v1()?)
            })
            // Two actual observer lifetime Arc allocations, including their
            // reference-count headers, coexist with the inline constructors.
            .and_then(|bytes| bytes.checked_add(2 * (3 * std::mem::size_of::<usize>())))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let mut demand = RootControllerPeerReceivingV1::fixed_demand()?
            .checked_add(RootControllerPeerCurrentSampleV1::demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        // All failed native owners remain resident. No descriptor or task
        // credit is inferred from archive completion or a later body result.
        for _ in 0..4 {
            demand = demand.checked_add(post)?;
        }
        if K::STOP_CLEANUP_ONLY {
            demand = demand.checked_add(crate::policy_compiler::stop_cleanup_root::transport::fixed_receiving_demand_v1()?)?;
        }
        Ok(demand)
    }

    pub(in crate::normal_root) fn capture_once_v1(
        &mut self,
        stream: &RetainedUnixStream,
    ) -> Result<(), Error> {
        if self.entered || self.final_entered || self.closed.is_some() {
            self.complete = false;
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.entered = true;
        self.funding = Some((|| {
            let mut receiving = self.startup.lock_receiving_v1()?;
            let returned = receiving.original_mut_v1().arm_purpose_peer_once_v1(self.startup, &mut self.admission);
            receiving.finish_returned_v1(returned)
        })());
        self.posts[0] = Some(self.observe_post(RootPurposePeerPostV1::AdmissionBefore));
        if matches!(self.funding, Some(Ok(())))
            && self
                .admission
                .is_positive_v1(RootPurposePeerPostV1::AdmissionBefore)
            && self.admission.require_armed_v1().is_ok()
        {
            // Construction occurs only after the complete same-R prepayment.
            self.peer = Some(RootControllerPeerReceivingV1::new(
                self.startup,
                ObserverLifetime::begin(),
            ));
            self.current = Some(RootControllerPeerCurrentSampleV1::new(
                ObserverLifetime::begin(),
            ));
            self.capture = Some(
                self.peer
                    .as_mut()
                    .ok_or(Error::Service)?
                    .capture_once(stream),
            );
        }
        self.posts[1] = Some(self.observe_post(RootPurposePeerPostV1::AdmissionAfter));
        if matches!(self.capture, Some(Ok(())))
            && self
                .admission
                .is_positive_v1(RootPurposePeerPostV1::AdmissionAfter)
            && self
                .admission
                .post_failure_v1(RootPurposePeerPostV1::AdmissionBefore)
                .is_none()
            && self
                .admission
                .post_failure_v1(RootPurposePeerPostV1::AdmissionAfter)
                .is_none()
        {
            self.initial_settlement = Some((|| {
                self.peer
                    .as_mut()
                    .ok_or(Error::Service)?
                    .settle_positive_once()?;
                self.admission.settle_admission_positive_v1()
            })());
        }
        if self.require_initial_v1().is_ok() {
            Ok(())
        } else {
            // No protocol body can follow a failed initial comparison. All
            // four destinations were already paid; close their remaining debt.
            let _owed = self.finish_posts_once_v1(stream);
            Err(Error::Service)
        }
    }

    pub(in crate::normal_root) fn require_initial_v1(&self) -> Result<(), Error> {
        if matches!(self.initial_settlement, Some(Ok(())))
            && self.closed.is_none()
            && self.admission.continuation_failure_v1().is_none()
            && self.admission.admission_failure_v1().is_none()
            && self
                .admission
                .post_failure_v1(RootPurposePeerPostV1::AdmissionBefore)
                .is_none()
            && self
                .admission
                .post_failure_v1(RootPurposePeerPostV1::AdmissionAfter)
                .is_none()
        {
            self.peer
                .as_ref()
                .ok_or(Error::Service)?
                .require_completed()
        } else {
            Err(Error::Service)
        }
    }

    pub(in crate::normal_root) fn peer_v1(
        &self,
    ) -> Result<&RootControllerPeerReceivingV1<'startup>, Error> {
        self.require_initial_v1()?;
        self.peer.as_ref().ok_or(Error::Service)
    }

    pub(in crate::normal_root) fn finish_posts_once_v1(
        &mut self,
        stream: &RetainedUnixStream,
    ) -> Result<(), Error> {
        if !self.entered || self.final_entered {
            self.complete = false;
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.final_entered = true;
        self.posts[2] = Some(self.observe_post(RootPurposePeerPostV1::FinalBefore));
        // This currentness sample was prearmed with the initial purpose, so
        // an earlier protocol/parser/refusal cannot suppress its native posts.
        if let (Some(peer), Some(sample)) = (&self.peer, &mut self.current) {
            if matches!(self.initial_settlement, Some(Ok(()))) {
                self.current_result = Some(peer.observe_prearmed_current_into_v1(stream, sample));
            }
        }
        self.posts[3] = Some(self.observe_post(RootPurposePeerPostV1::FinalAfter));
        if self.failure().is_none() && matches!(self.current_result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Error::Service)
        }
    }

    // The real D protocol owner calls this only after its own complete positive
    // conjunction. This retires comparison custody, never a lifecycle grant.
    pub(in crate::normal_root) fn settle_positive_once_v1(&mut self) -> Result<(), Error> {
        if self.complete
            || !self.final_entered
            || self.failure().is_some()
            || !matches!(self.current_result, Some(Ok(())))
            || !self
                .admission
                .is_positive_v1(RootPurposePeerPostV1::FinalBefore)
            || !self
                .admission
                .is_positive_v1(RootPurposePeerPostV1::FinalAfter)
        {
            self.complete = false;
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.final_settlement = Some((|| {
            self.current
                .as_mut()
                .ok_or(Error::Service)?
                .settle_after_root_post_once_v1()?;
            self.admission.settle_final_positive_v1()
        })());
        self.complete = matches!(self.final_settlement, Some(Ok(()))) && self.failure().is_none();
        if self.complete {
            Ok(())
        } else {
            Err(Error::Service)
        }
    }

    // Only the actual settled native owner can satisfy a continuation's
    // financial disposal check. It borrows no startup InitialController slot.
    pub(crate) fn require_completed_for_root_disposal_v1(
        &self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        if !std::ptr::eq(self.startup, startup)
            || !self.complete
            || !self.final_entered
            || !matches!(self.initial_settlement, Some(Ok(())))
            || !matches!(self.final_settlement, Some(Ok(())))
            || self.failure().is_some()
        {
            return Err(Error::Service);
        }
        Ok(())
    }

    pub(in crate::normal_root) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let first = self.failure()?;
        if let Some(peer) = &self.peer {
            if peer
                .failure()
                .is_some_and(|cause| std::ptr::addr_eq(first as *const _, cause as *const _))
            {
                return peer.property_failure_view_v1();
            }
        }
        if let Some(current) = &self.current {
            if current
                .failure()
                .is_some_and(|cause| std::ptr::addr_eq(first as *const _, cause as *const _))
            {
                return current.property_failure_view_v1();
            }
        }
        None
    }

    fn observe_post(&mut self, purpose: RootPurposePeerPostV1) -> Result<(), Error> {
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1()
            .observe_purpose_peer_post_once_v1(self.startup, &mut self.admission, purpose);
        receiving.finish_returned_v1(returned)
    }

    pub(in crate::normal_root) fn primary_failure_v1(&self) -> Option<&(dyn StdError + 'static)> {
        self.admission
            .admission_failure_v1()
            .or_else(|| error(&self.funding))
            .or_else(|| {
                self.admission
                    .post_failure_v1(RootPurposePeerPostV1::AdmissionBefore)
            })
            .or_else(|| error(&self.posts[0]))
            .or_else(|| self.peer.as_ref().and_then(|peer| peer.failure()))
            .or_else(|| error(&self.capture))
            .or_else(|| {
                self.admission
                    .post_failure_v1(RootPurposePeerPostV1::AdmissionAfter)
            })
            .or_else(|| error(&self.posts[1]))
            .or_else(|| error(&self.initial_settlement))
    }

    pub(in crate::normal_root) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.primary_failure_v1()
            .or_else(|| self.admission.continuation_failure_v1())
            .or_else(|| {
                self.admission
                    .post_failure_v1(RootPurposePeerPostV1::FinalBefore)
            })
            .or_else(|| error(&self.posts[2]))
            .or_else(|| self.current.as_ref().and_then(|sample| sample.failure()))
            .or_else(|| error(&self.current_result))
            .or_else(|| {
                self.admission
                    .post_failure_v1(RootPurposePeerPostV1::FinalAfter)
            })
            .or_else(|| error(&self.posts[3]))
            .or_else(|| error(&self.final_settlement))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn error<T, E: StdError + 'static>(
    value: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl<K: RootPeerPurposeV1> Drop for RootPurposeControllerPeerReceivingV1<'_, K> {
    fn drop(&mut self) {
        if self.entered && !self.complete {
            // Retain the whole failed/unfinished native purpose through
            // intentional process termination before any field unwinds.
            std::process::abort();
        }
    }
}

impl<'startup, K: stages::RootProvisioningPurposeV1> RootPurposeControllerPeerReceivingV1<'startup, K> {
    pub(in crate::normal_root) fn stage_receiving_v1(&mut self) -> Result<stages::RootProvisioningStageReceivingV1<'_, 'startup, K>, Error> {
        self.require_initial_v1()?;
        Ok(stages::RootProvisioningStageReceivingV1 {
            startup: self.startup,
            admission: &mut self.admission,
            resident_baseline: ResourceVector::ZERO,
            delete_final_cache: false,
        })
    }
}

impl<'startup> RootPurposeControllerPeerReceivingV1<'startup, DeleteRootPeerPurposeV1> {
    pub(in crate::normal_root) fn cache_stage_receiving_v2(&mut self,
        challenge: &crate::policy_compiler::delete_root::RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
        floor: &crate::policy_compiler::delete_root::RootDeleteFloorOriginalV1,
        transfer: &crate::policy_compiler::delete_root::RootDeleteTransferNamespaceOriginalV1,
    ) -> Result<RootDeleteCacheStageReceivingV2<'_, 'startup>, Error> {
        self.require_initial_v1()?;
        let resident_baseline = (|| {
            let mut sum = ResourceVector::ZERO;
            for retained in [challenge.retained_receiving_demand_v1()?, controller.retained_receiving_demand_v1()?,
                source.retained_receiving_demand_v1()?, floor.retained_receiving_demand_v1()?,
                transfer.held_receiving_demand_v2()?] {
                sum = sum.checked_add(aos_sandbox_model::component_receiving::without_operation_traffic_v1(retained))?;
            }
            Ok::<_, ResourceReservationErrorV1>(sum)
        })().map_err(|_| Error::Service)?;
        Ok(stages::RootProvisioningStageReceivingV1 { startup: self.startup,
            admission: &mut self.admission, resident_baseline,
            delete_final_cache: source.is_final_read_v2() })
    }
}

impl<'startup> RootPurposeControllerPeerReceivingV1<'startup, FinalityRecoverRootPeerPurposeV1> {
    pub(in crate::normal_root) fn finality_recover_stage_receiving_v1(&mut self)
        -> Result<stages::RootFinalityRecoverStageReceivingV1<'_, 'startup>, Error> {
        self.require_initial_v1()?;
        Ok(stages::RootFinalityRecoverStageReceivingV1::new_v1(self.startup, &mut self.admission))
    }
}

/// Binds a read-only Start policy-input peer to its actual new native flight.
pub(crate) type RootStartAssignmentInputsControllerPeerReceivingV2<'startup> =
    RootPurposeControllerPeerReceivingV1<'startup,
        crate::controller_resource_reservation::StartAssignmentInputsRootPeerPurposeV2>;

impl<'startup> RootStartAssignmentInputsControllerPeerReceivingV2<'startup> {
    pub(in crate::normal_root) fn start_assignment_inputs_stage_receiving_v2(&mut self)
        -> Result<RootStartAssignmentInputsStageReceivingV2<'_, 'startup>, Error>
    {
        self.require_initial_v1()?;
        Ok(RootStartAssignmentInputsStageReceivingV2::new_v2(self.startup, &mut self.admission))
    }
}
