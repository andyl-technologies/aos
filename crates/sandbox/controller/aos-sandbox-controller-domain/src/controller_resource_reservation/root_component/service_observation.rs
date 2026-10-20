//! Charges each actual Root service read and retains its prearmed owed post.
//!
//! Five closed startup purposes have one future post each. Their native owner
//! is armed only after the same R pays both its extra resident peak and traffic.
//! A refused primary never needs a healthy reentry or another debit to run it.

use std::error::Error as StdError;
use std::sync::Arc;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootPrearmedHistoryServicePostV1};
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1,
    RootServiceCurrentnessV1};
use super::{RootReceivingOriginalV1, ResourceReservationErrorV1};

#[derive(Clone, Copy)]
pub(super) enum RootServicePostPurposeV1 {
    Journal,
    Credentials,
    AuthorityWriter,
    PolicyWriter,
    InitialController,
}

impl RootServicePostPurposeV1 {
    fn index(self) -> usize {
        match self {
            Self::Journal => 0,
            Self::Credentials => 1,
            Self::AuthorityWriter => 2,
            Self::PolicyWriter => 3,
            Self::InitialController => 4,
        }
    }
}

#[derive(Default)]
struct ServicePostV1 {
    funding: Option<Result<(), Arc<ResourceReservationErrorV1>>>,
    original: Option<Result<RootPrearmedHistoryServicePostV1, RootObservationErrorV1>>,
    returned: Option<Result<(), Error>>,
}

impl ServicePostV1 {
    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.funding.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause.as_ref() as _)
            .or_else(|| self.original.as_ref().and_then(|result| match result {
                Ok(original) => original.failure(), Err(cause) => Some(cause as _),
            }))
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

#[derive(Default)]
pub(super) struct RootServiceObservationsV1 {
    resident: Option<Result<(), Arc<ResourceReservationErrorV1>>>,
    recheck: Option<Result<(), Arc<ResourceReservationErrorV1>>>,
    first_payment: Option<Arc<ResourceReservationErrorV1>>,
    posts: [Option<ServicePostV1>; 5],
}

impl RootServiceObservationsV1 {
    pub(super) fn payment_failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.first_payment.as_ref().map(|cause| cause.as_ref() as _)
    }
}

fn traffic(demand: ResourceVector) -> ResourceVector {
    ResourceVector::ZERO.with(D::NetworkBytes, demand.get(D::NetworkBytes))
        .with(D::LogBytes, demand.get(D::LogBytes))
        .with(D::PublicationStagingBytes, demand.get(D::PublicationStagingBytes))
        .with(D::OutputBytes, demand.get(D::OutputBytes))
}

fn post_resident_demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
    let demand = RootPrearmedHistoryServicePostV1::demand_v1().ok_or_else(invalid)?;
    let paid_worker = RootServiceCurrentnessV1::demand()?.get(D::Pids);
    if demand.get(D::Pids) > paid_worker { return Err(invalid()); }
    // Selected startup already paid this sequential worker. Every central read
    // holds the same R mutex until archive.read has joined its actual worker.
    // Healthy entry also refuses while a separate history worker interval is
    // active. Failed runtimes/FDs stay charged in the full extra native peak;
    // only the simultaneous task count reuses the original one-worker slot.
    Ok(crate::normal_root::root_history_post::without_traffic(demand).with(D::Pids, 0))
}

impl RootReceivingOriginalV1 {
    fn retain_service_payment_failure_v1(&mut self, cause: ResourceReservationErrorV1)
        -> Arc<ResourceReservationErrorV1>
    {
        let cause = if let Some(original) = &self.native_receiving_refusal {
            Arc::clone(original)
        } else {
            let original = Arc::new(cause);
            self.native_receiving_refusal = Some(Arc::clone(&original));
            original
        };
        self.service_observations.first_payment.get_or_insert_with(|| Arc::clone(&cause));
        self.activation.latch_root_refusal_v1();
        cause
    }

    fn service_worker_idle_v1(&self) -> bool {
        self.controller_peer_provision.is_none()
            || self.activation.controller_history_worker_idle_data_v1()
    }

    pub(super) fn prepay_service_recheck_once_v1(&mut self) -> Result<(), Error> {
        if !self.service_worker_idle_v1() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let result = RootServiceCurrentnessV1::demand()
            .and_then(|demand| self.debit_observer_traffic_v1(traffic(demand)));
        let returned = match result {
            Ok(()) => Ok(()),
            Err(cause) => Err(self.retain_service_payment_failure_v1(cause)),
        };
        // Prior positive unit/error-handle storage is inert and is retired
        // outside N. first_payment retains the first failed actual cause.
        drop(self.service_observations.recheck.take());
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.service_observations.recheck, returned,
        );
        match &self.service_observations.recheck {
            Some(Ok(())) => Ok(()),
            Some(Err(cause)) => Err(Error::ServiceReceiving(Arc::clone(cause))),
            None => Err(Error::Service),
        }
    }

    fn service_post_may_arm_v1(&self, purpose: RootServicePostPurposeV1) -> bool {
        match purpose {
            RootServicePostPurposeV1::Journal => self.journal_receiving.as_ref()
                .is_some_and(|stage| stage.may_arm_service_post_v1()),
            RootServicePostPurposeV1::Credentials => self.credential_receiving.as_ref()
                .is_some_and(|stage| stage.may_arm_service_post_v1()),
            RootServicePostPurposeV1::AuthorityWriter => self.current_writers_receiving.as_ref()
                .is_some_and(|stage| stage.may_arm_service_post_v1(0)),
            RootServicePostPurposeV1::PolicyWriter => self.current_writers_receiving.as_ref()
                .is_some_and(|stage| stage.may_arm_service_post_v1(1)),
            RootServicePostPurposeV1::InitialController => self.controller_peer_provision.as_ref()
                .is_some_and(|stage| stage.may_arm_service_post_v1()),
        }
    }

    pub(super) fn arm_service_post_once_v1(&mut self, startup: &ProductionNormalRootStartupV1,
        purpose: RootServicePostPurposeV1) -> Result<(), Error>
    {
        let index = purpose.index();
        if self.failure().is_some() || !self.service_worker_idle_v1()
            || !self.service_post_may_arm_v1(purpose)
            || self.service_observations.posts[index].is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.service_observations.posts[index] = Some(Default::default());
        if self.service_observations.resident.is_none() {
            let result = post_resident_demand()
                .and_then(|demand| self.debit_native_journal_representation_v1(demand));
            let returned = match result {
                Ok(()) => Ok(()), Err(cause) => Err(self.retain_service_payment_failure_v1(cause)),
            };
            self.native_refusal_original_v1().park_empty_result_v1(
                &mut self.service_observations.resident, returned,
            );
        }
        if let Some(Err(cause)) = &self.service_observations.resident {
            return Err(Error::ServiceReceiving(Arc::clone(cause)));
        }
        let result = RootServiceCurrentnessV1::demand()
            .and_then(|demand| self.debit_observer_traffic_v1(traffic(demand)));
        let funding = match result {
            Ok(()) => Ok(()), Err(cause) => Err(self.retain_service_payment_failure_v1(cause)),
        };
        let failure = funding.as_ref().err().map(Arc::clone);
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.service_observations.posts[index].as_mut().ok_or(Error::Service)?.funding, funding,
        );
        if let Some(cause) = failure { return Err(Error::ServiceReceiving(cause)); }
        let original = self.activation.arm_history_service_post_v1(startup.native_startup_original_v1());
        let positive = original.is_ok();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.service_observations.posts[index].as_mut().ok_or(Error::Service)?.original, original,
        );
        if positive { Ok(()) } else { self.activation.latch_root_refusal_v1(); Err(Error::Service) }
    }

    pub(super) fn service_post_is_armed_v1(&self, purpose: RootServicePostPurposeV1) -> bool {
        self.service_observations.posts[purpose.index()].as_ref().is_some_and(|post|
            matches!(post.funding, Some(Ok(()))) && matches!(post.original, Some(Ok(_))))
    }

    pub(super) fn observe_service_post_once_v1(&mut self, startup: &ProductionNormalRootStartupV1,
        purpose: RootServicePostPurposeV1) -> Result<(), Error>
    {
        let refusal = self.native_refusal_original_v1();
        let post = self.service_observations.posts[purpose.index()].as_mut().ok_or(Error::Service)?;
        if post.returned.is_some() || !matches!(post.funding, Some(Ok(()))) {
            return Err(Error::Service);
        }
        let original = post.original.as_mut().and_then(|result| result.as_mut().ok()).ok_or(Error::Service)?;
        // No healthy R check or new debit occurs here. The original lower
        // association admits only this prepaid negative-capable observation.
        let returned = self.activation.observe_history_service_post_once_v1(
            startup.native_startup_original_v1(), original).map_err(Into::into);
        refusal.park_empty_result_v1(&mut post.returned, returned);
        if matches!(post.returned, Some(Ok(()))) { Ok(()) } else { Err(Error::Service) }
    }

    pub(super) fn service_post_arm_failure_v1(&self, purpose: RootServicePostPurposeV1)
        -> Option<&(dyn StdError + 'static)>
    {
        let post = self.service_observations.posts[purpose.index()].as_ref()?;
        post.funding.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause.as_ref() as _)
            .or_else(|| post.original.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    pub(super) fn service_post_failure_v1(&self, purpose: RootServicePostPurposeV1)
        -> Option<&(dyn StdError + 'static)>
    {
        self.service_observations.posts[purpose.index()].as_ref()?.failure()
    }

    fn service_post_may_retire_v1(&self, purpose: RootServicePostPurposeV1) -> bool {
        match purpose {
            RootServicePostPurposeV1::Journal => self.journal_receiving.as_ref()
                .is_some_and(|stage| stage.service_post_can_retire_v1()),
            RootServicePostPurposeV1::Credentials => self.credential_receiving.as_ref()
                .is_some_and(|stage| stage.service_post_can_retire_v1()),
            RootServicePostPurposeV1::AuthorityWriter => self.current_writers_receiving.as_ref()
                .is_some_and(|stage| stage.service_post_can_retire_v1(0)),
            RootServicePostPurposeV1::PolicyWriter => self.current_writers_receiving.as_ref()
                .is_some_and(|stage| stage.service_post_can_retire_v1(1)),
            RootServicePostPurposeV1::InitialController => self.controller_peer_provision.as_ref()
                .is_some_and(|stage| stage.service_post_can_retire_v1()),
        }
    }

    // Sole call sites are the named purpose's actual positive completion
    // branches, after their native names/replay/capture/settlement posts.
    pub(super) fn retire_service_post_after_positive_v1(&mut self, purpose: RootServicePostPurposeV1) {
        if !self.service_post_may_retire_v1(purpose) { return; }
        if let Some(post) = self.service_observations.posts[purpose.index()].as_mut() {
            if matches!(post.returned, Some(Ok(()))) && post.failure().is_none() {
                if let Some(Ok(original)) = &mut post.original { original.retire_positive_once_v1(); }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_service_row_traffic_never_reuses_resident_credit() {
        let complete = RootServiceCurrentnessV1::demand().unwrap();
        let spent = traffic(complete);
        assert!(spent.get(D::NetworkBytes) > 0);
        assert!(spent.get(D::LogBytes) > 0);
        for dimension in D::ALL {
            if matches!(dimension, D::NetworkBytes | D::LogBytes | D::PublicationStagingBytes | D::OutputBytes) {
                assert_eq!(spent.get(dimension), complete.get(dimension));
            } else {
                assert_eq!(spent.get(dimension), 0);
            }
        }
        let native = RootPrearmedHistoryServicePostV1::demand_v1().unwrap();
        let resident = post_resident_demand().unwrap();
        assert_eq!(resident.get(D::OpenFiles), native.get(D::OpenFiles));
        assert_eq!(resident.get(D::MemoryBytes), native.get(D::MemoryBytes));
        assert_eq!(resident.get(D::Pids), 0);
        assert_eq!(resident.get(D::NetworkBytes), 0);
        assert_eq!(resident.get(D::LogBytes), 0);
    }

    #[test]
    fn returned_service_debit_error_keeps_the_same_resident_cause() {
        let cause = Arc::new(ResourceReservationErrorV1::Conflict);
        let owner = RootServiceObservationsV1 { first_payment: Some(Arc::clone(&cause)),
            ..Default::default() };
        let returned = Error::ServiceReceiving(Arc::clone(&cause));
        let resident = owner.payment_failure().unwrap()
            .downcast_ref::<ResourceReservationErrorV1>().unwrap();
        assert!(std::ptr::eq(resident, cause.as_ref()));
        match &returned {
            Error::ServiceReceiving(actual) => assert!(Arc::ptr_eq(actual, &cause)),
            _ => panic!("wrong classification"),
        }
        drop(returned);
        assert!(std::ptr::eq(owner.payment_failure().unwrap()
            .downcast_ref::<ResourceReservationErrorV1>().unwrap(), cause.as_ref()));
    }
}
