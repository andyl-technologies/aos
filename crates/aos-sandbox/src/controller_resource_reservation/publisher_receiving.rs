//! Owns recurring selected Publisher receiving under the SAME original C/B.
//!
//! A permanently reserved finite capacity backs one exclusive operation at a
//! time. Every actual operation consumes its full admitted shape before any
//! RPC. The original profile, process bus observations and fixed native sample
//! stay together through independent posts; only whole positive disposition
//! and actual sample disposal permit a later flight. There is no new account,
//! copied payer, cumulative lifetime traffic counter or capacity refund.

use std::sync::Arc;

use super::publisher_environment::ControllerPublisherBusEnvironmentV1;
use aos_sandbox_broker::fixed_service_identity::ServiceIdentityFlightV1;
use super::ResourceReservationErrorV1;
use aos_sandbox_broker::controller_receiving::{
    ControllerPublisherOperationReceivingV1, ControllerReceivingOriginalV1,
};
use crate::normal_root::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use crate::publisher_admin::registration::PublisherServiceRegistration;
use aos_sandbox_publisher::publisher_sessions::PublisherSessionScope;


type ProducerResultV1 = Result<([u8; 16], [u8; 16]), NormalRootStartupErrorV1>;

/// Describes the actual protected Publisher credential selected by Runtime.
///
/// These identity DATA authorize no growth or service. Only the genuine
/// opening can construct a receiving original and join its admitted profile.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerPublisherStartupDataV1 {
    /// Actual protected principal/node/project/cache binding.
    pub scope: PublisherSessionScope,
    /// Actual protected service user identifier.
    pub uid: u32,
    /// Actual protected service group identifier.
    pub gid: u32,
}

#[derive(Clone, Copy)]
enum FirstFailureV1 {
    Preparation,
    Begin,
    EnvironmentBefore,
    Consumption,
    ProducerBefore,
    Native,
    ProducerAfter,
    EnvironmentAfter,
    Binding,
    Transfer,
    Finish,
    Reentry,
}

/// Retains the one recurring Publisher native/financial receiver.
///
/// No public constructor exists. Only the SAME successful original bank
/// opening can prepare this owner; numeric DATA cannot construct a payer.
#[doc(hidden)]
pub struct ControllerPublisherReceivingV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    startup: ControllerPublisherStartupDataV1,
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    begin: Option<Result<(), ResourceReservationErrorV1>>,
    receiving: ControllerPublisherOperationReceivingV1,
    environment: ControllerPublisherBusEnvironmentV1,
    producer_before_job: Option<tokio::task::JoinHandle<ProducerResultV1>>,
    producer_before: Option<Result<ProducerResultV1, tokio::task::JoinError>>,
    producer_after_job: Option<tokio::task::JoinHandle<ProducerResultV1>>,
    producer_after: Option<Result<ProducerResultV1, tokio::task::JoinError>>,
    consumption: Option<Result<(), ResourceReservationErrorV1>>,
    sample: Option<ServiceIdentityFlightV1>,
    native: Option<Result<(), super::service_identity::ServiceIdentityRefusalV1>>,
    binding: Option<Result<(), ResourceReservationErrorV1>>,
    output: Option<Option<PublisherServiceRegistration>>,
    transfer: Option<Result<(), ResourceReservationErrorV1>>,
    finish: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<FirstFailureV1>,
    observing: bool,
    ended: bool,
}

impl ControllerPublisherReceivingV1 {
    /// Reports the SAME actual operation supplier's requested comparison DATA.
    ///
    /// This constructs no original, account, loan or permission to perform IO.
    ///
    /// # Errors
    /// Rejects incomplete or overflowing concrete operation representation.
    #[doc(hidden)]
    pub fn operation_requested_counts_v1() -> Result<
        super::runtime_receiving::ControllerRuntimeRequestedCountsV1,
        ResourceReservationErrorV1,
    > {
        ControllerPublisherOperationReceivingV1::requested_counts_v1().map_err(Into::into)
    }

    pub(super) fn new(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        startup: ControllerPublisherStartupDataV1,
    ) -> Self {
        let receiving = ControllerPublisherOperationReceivingV1::new(Arc::clone(&original));
        Self {
            original,
            profile,
            startup,
            preparation: None,
            begin: None,
            receiving,
            environment: ControllerPublisherBusEnvironmentV1::new(),
            producer_before_job: None,
            producer_before: None,
            producer_after_job: None,
            producer_after: None,
            consumption: None,
            sample: None,
            native: None,
            binding: None,
            output: None,
            transfer: None,
            finish: None,
            first: None,
            observing: false,
            ended: false,
        }
    }

    pub(super) fn prepare_once(&mut self) -> Result<(), ()> {
        if self.preparation.is_some() {
            self.first.get_or_insert(FirstFailureV1::Reentry);
            return Err(());
        }
        let scope = self.startup.scope;
        self.preparation = Some(self.receiving.prepare_once(
            self.profile.lower_original_v1(),
            aos_sandbox_broker::controller_receiving::ControllerPublisherStartupDataV1 {
                scope: aos_sandbox_protocol::publisher_session::PublisherSessionScope {
                    principal: scope.principal, node: scope.node,
                    project: scope.project, cache_resource: scope.cache_resource,
                },
                uid: self.startup.uid, gid: self.startup.gid,
            },
        ).map_err(Into::into));
        if matches!(self.preparation, Some(Err(_))) {
            self.first.get_or_insert(FirstFailureV1::Preparation);
            self.receiving.fence();
            Err(())
        } else {
            Ok(())
        }
    }

    pub(super) fn is_prepared(&self) -> bool {
        matches!(self.preparation, Some(Ok(()))) && self.first.is_none()
    }

    /// Begins the actual next operation before its future Box or Native IO.
    ///
    /// The finite reservation already backs both actual process environment
    /// copies. Unsupported effective addresses fail before future/connection
    /// construction; no default absence is inferred from a unit file.
    ///
    /// # Errors
    /// Keeps prior whole failure, unfinished operation or refused original
    /// capacity resident. Refuses reentry, unsupported address or bad phase.
    pub fn begin_observation_once(&mut self) -> Result<(), ()> {
        if !matches!(self.preparation, Some(Ok(())))
            || self.observing
            || self.first.is_some()
            || self.output.is_some()
            || self.sample.is_some()
            || !self.receiving.can_begin_v1()
        {
            self.first.get_or_insert(FirstFailureV1::Reentry);
            self.receiving.fence();
            return Err(());
        }
        // Only a previous complete same-owner positive flight reaches here.
        // Its native sample has ALREADY been dropped, and its normal output
        // moved into Runtime's prepaid one-session destination.
        self.begin = Some(self.receiving.begin_operation_once().map_err(Into::into));
        if !matches!(self.begin, Some(Ok(()))) {
            self.first.get_or_insert(FirstFailureV1::Begin);
            self.receiving.fence();
            return Err(());
        }
        self.environment = ControllerPublisherBusEnvironmentV1::new();
        if self.environment.capture_initial().is_err() {
            self.first.get_or_insert(FirstFailureV1::EnvironmentBefore);
            // The independent effective-environment post still runs even when
            // no selected connection or future is permitted to be constructed.
            let _post = self.environment.capture_final();
            self.receiving.fence();
            return Err(());
        }
        self.producer_before_job = None;
        self.producer_before = None;
        self.producer_after_job = None;
        self.producer_after = None;
        self.consumption = None;
        self.native = None;
        self.binding = None;
        self.transfer = None;
        self.finish = None;
        self.ended = false;
        self.observing = true;
        Ok(())
    }

    /// Runs the same exclusive full-shape operation and returns its whole owner.
    ///
    /// No authority mutex or detached grant crosses an await. Native failures,
    /// timeouts and independent posts stay in this returned original; an
    /// unfinished future closes it through Drop rather than creating a retry.
    ///
    /// # Panics
    /// Panics if polled without the actual prepaid main Tokio drivers enabled.
    pub async fn observe(mut self) -> Self {
        self.observe_inner().await;
        self
    }

    async fn observe_inner(&mut self) {
        if !self.observing || self.first.is_some() {
            self.first.get_or_insert(FirstFailureV1::Reentry);
            self.receiving.fence();
            return;
        }
        self.consumption = Some(self.receiving.consume_native_once().map_err(Into::into));
        if matches!(self.consumption, Some(Err(_))) {
            self.first.get_or_insert(FirstFailureV1::Consumption);
        }
        // ALL traffic, including these original recipient bookends, follows
        // once-consumption. A refused loan performs no profile RPC or connect.
        if self.first.is_none() {
            // The admitted profile reader owns and disposes a private Tokio
            // runtime. Run its synchronous interval outside this async context
            // on the SAME prepaid blocking pool. This one owned future awaits
            // each job to completion, even after the worker's first timeout;
            // it cannot abandon a job and enqueue another observation.
            let profile = Arc::clone(&self.profile);
            let original = Arc::clone(&self.original);
            self.producer_before_job = Some(tokio::task::spawn_blocking(move || {
                profile.require_publisher_resource_producer(&original)
            }));
            self.producer_before = match self.producer_before_job.as_mut() {
                Some(job) => Some(job.await),
                None => None,
            };
            if !matches!(self.producer_before, Some(Ok(Ok(_)))) {
                self.first.get_or_insert(FirstFailureV1::ProducerBefore);
            }
            if self.first.is_none() {
                self.sample = Some(ServiceIdentityFlightV1::publisher(
                    self.startup.uid, self.startup.gid,
                ));
                if let Some(sample) = self.sample.as_mut() {
                    self.native = Some(sample.observe_once().await);
                    if matches!(self.native, Some(Err(_))) {
                        self.first.get_or_insert(FirstFailureV1::Native);
                    }
                }
            }
            let profile = Arc::clone(&self.profile);
            let original = Arc::clone(&self.original);
            self.producer_after_job = Some(tokio::task::spawn_blocking(move || {
                profile.require_publisher_resource_producer(&original)
            }));
            self.producer_after = match self.producer_after_job.as_mut() {
                Some(job) => Some(job.await),
                None => None,
            };
            if !matches!(self.producer_after, Some(Ok(Ok(_)))) {
                self.first.get_or_insert(FirstFailureV1::ProducerAfter);
            }
        }
        // This independent process post uses separate retained bytes even if
        // an earlier Native/profile/semantic stage failed.
        if self.environment.capture_final().is_err() {
            self.first.get_or_insert(FirstFailureV1::EnvironmentAfter);
        }
        self.binding = Some(match (&self.producer_before, &self.producer_after) {
            (Some(Ok(Ok(before))), Some(Ok(Ok(after)))) if before == after =>
                self.receiving.require_recipient_v1(after.0, after.1).map_err(Into::into),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if matches!(self.binding, Some(Err(_))) {
            self.first.get_or_insert(FirstFailureV1::Binding);
        }
        if self.first.is_none() && self.sample.as_ref().is_some_and(
            ServiceIdentityFlightV1::completed_positive,
        ) {
            self.output = self.sample.as_mut()
                .and_then(ServiceIdentityFlightV1::take_publisher_native)
                .map(|native| native.map(|native| {
                    let (anchor, expected_process) = native.into_parts();
                    PublisherServiceRegistration {
                        scope: self.startup.scope,
                        anchor,
                        expected_process,
                    }
                }));
            self.transfer = Some(if self.output.is_some() {
                Ok(())
            } else {
                Err(ResourceReservationErrorV1::Conflict)
            });
            if self.output.is_none() {
                self.first.get_or_insert(FirstFailureV1::Transfer);
            } else {
                // The same normal output is parked first. Dispose the ACTUAL
                // native sample, including all original bounded transports,
                // cgroup/pidfd/probes and membership buffers before finishing.
                drop(self.sample.take());
                self.finish = Some(self.receiving.complete_after_sample_disposal_once().map_err(Into::into));
                if matches!(self.finish, Some(Err(_))) {
                    self.first.get_or_insert(FirstFailureV1::Finish);
                }
                self.observing = false;
                self.ended = true;
                if self.first.is_some() {
                    self.receiving.fence();
                }
                return;
            }
        }
        self.receiving.fence();
        self.observing = false;
        self.ended = true;
    }

    /// Moves the same successful locator/absence after all original posts.
    pub fn take_completed_registration(&mut self) -> Option<Option<PublisherServiceRegistration>> {
        if self.first.is_some()
            || !self.ended
            || !matches!(self.finish, Some(Ok(())))
            || !self.receiving.completed_positive_v1()
        {
            return None;
        }
        self.output.take()
    }

    /// Borrows the first original financial, environment or native failure.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            FirstFailureV1::Preparation => self.receiving.preparation_failure_v1().or_else(|| original_error(&self.preparation)),
            FirstFailureV1::Begin => self.receiving.begin_failure_v1().or_else(|| original_error(&self.begin)),
            FirstFailureV1::EnvironmentBefore => self.environment.failure()
                .map(|error| error as &dyn std::error::Error),
            FirstFailureV1::Consumption => self.receiving.consumption_failure_v1()
                .or_else(|| original_error(&self.consumption))
                .or(Some(&ResourceReservationErrorV1::Conflict)),
            FirstFailureV1::ProducerBefore => producer_error(&self.producer_before),
            FirstFailureV1::Native => self.sample.as_ref().and_then(ServiceIdentityFlightV1::failure)
                .or_else(|| original_error(&self.native)),
            FirstFailureV1::ProducerAfter => producer_error(&self.producer_after),
            FirstFailureV1::EnvironmentAfter => self.environment.failure()
                .map(|error| error as &dyn std::error::Error),
            FirstFailureV1::Binding => original_error(&self.binding),
            FirstFailureV1::Transfer => original_error(&self.transfer),
            FirstFailureV1::Finish => self.receiving.finish_failure_v1().or_else(|| original_error(&self.finish)),
            FirstFailureV1::Reentry => Some(&ResourceReservationErrorV1::Conflict),
        }
    }
}

impl Drop for ControllerPublisherReceivingV1 {
    fn drop(&mut self) {
        if self.observing || self.first.is_some() {
            self.receiving.fence();
        }
    }
}

fn producer_error(
    result: &Option<Result<ProducerResultV1, tokio::task::JoinError>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    match result.as_ref()? {
        Err(cause) => Some(cause),
        Ok(Err(cause)) => Some(cause),
        Ok(Ok(_)) => None,
    }
}

fn original_error<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err())
        .map(|error| error as &dyn std::error::Error)
}

