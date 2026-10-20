//! Owns one Start resource purpose through its actual Root upper End.

use super::{
    RootHostLaunchOpeningOriginalV2,
    final_exchange::RootStartResourceFinalExchangeOriginalV2,
    native::{Phase, RootStartResourceNativeOriginalV2},
};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::NormalRootStartupErrorV1;
use crate::policy_compiler::{
    RootCurrentPolicyInputDataV1, bounded_stream_io::DeadlineStreamDirectionV1,
    root_policy_prelude::RootHostLaunchPreludeV1,
};
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::ResourceCompletionProofDataV2;
use std::error::Error;

type Cause = Box<dyn Error>;
type Stop = crate::policy_compiler::create_storage_current::RootCreateStorageCurrentErrorV1;

#[derive(Clone, Copy)]
pub(super) enum First {
    Opening,
    Native(Phase),
    Financial,
    Body(bool),
}

/// Retains the actual accepted Start's resource Root flight through final posts.
///
/// The unsigned reply leaves the same purpose occupied. Only independently
/// verified63/19, native final cuts, strict EOF, all posts and actual upper
/// socket disposal complete it. Parsed proof DATA cannot construct this owner.
pub struct RootStartResourceReceivingV2<'flight, 'listener, 'startup> {
    pub(super) prelude: RootHostLaunchPreludeV1<'flight, 'listener, 'startup>,
    pub(super) opening: RootHostLaunchOpeningOriginalV2,
    pub(super) peer: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) native: Option<Box<RootStartResourceNativeOriginalV2>>,
    pub(super) unsigned: Option<Result<(), Cause>>,
    pub(super) final_result: Option<Result<(), Cause>>,
    pub(super) first: Option<First>,
    pub(super) negative: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) negative_disposition: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) closed: bool,
}

impl<'flight, 'listener, 'startup> RootStartResourceReceivingV2<'flight, 'listener, 'startup> {
    pub(crate) fn from_prelude_v2(
        prelude: RootHostLaunchPreludeV1<'flight, 'listener, 'startup>,
    ) -> Self {
        Self {
            prelude,
            opening: Default::default(),
            peer: None,
            native: None,
            unsigned: None,
            final_result: None,
            first: None,
            negative: None,
            negative_disposition: None,
            closed: false,
        }
    }

    /// Receives current Start originals and sends the independently normalized plan.
    ///
    /// # Errors
    /// Refuses another purpose, unavailable same-R payment, changed originals,
    /// policy, fresh lease, native cuts or original deadline; custody is retained.
    pub fn receive_unsigned_once_v2(
        &mut self,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Stop> {
        if self.peer.is_some() || self.closed {
            self.closed = true;
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        let root = &mut self.prelude.original;
        self.peer = Some(root.flight.admit_host_launch_controller_peer_once_v1());
        if !matches!(self.peer, Some(Ok(()))) {
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        self.unsigned = Some((|| {
            self.opening.admit_query_once_v1(
                &mut root.flight.host_launch_stage_receiving_v1()?,
                std::mem::size_of::<RootStartResourceNativeOriginalV2>(),
            )?;
            self.native = Some(Box::new(RootStartResourceNativeOriginalV2::new()));
            super::unsigned::receive_once_v2(
                &mut self.opening,
                self.native
                    .as_mut()
                    .ok_or(JournalError::ProtectedBoundary)?,
                root,
                policy,
            )
        })());
        self.select_failure(false);
        let _owed = self.prelude.original.native.finish_opening_if_owed_v1();
        if !matches!(self.unsigned, Some(Ok(()))) || self.failure().is_some() {
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        Ok(())
    }

    /// Verifies the actual resource Session and sends its final acknowledgement.
    ///
    /// # Errors
    /// Refuses substituted packets/cuts, stale signed policy or current Start,
    /// a failed independent post, expired original horizon or ambiguous IO.
    pub fn receive_final_once_v2(
        &mut self,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Stop> {
        if self.closed
            || !matches!(self.unsigned, Some(Ok(())))
            || self.final_result.is_some()
            || self.failure().is_some()
        {
            self.closed = true;
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        let root = &mut self.prelude.original;
        let native = self.native.as_mut().ok_or(Stop::Ready)?;
        native.phase = Phase::Final;
        self.final_result = Some((|| {
            // The fixed header and receiver live in the original paid native
            // owner; HostPlan prepaid their traffic before the unsigned send.
            let sample = native
                .clock
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .check_next_once_v1()?;
            self.opening.require_current_clock_v1(sample)?;
            native.final_header_io.run_once(
                &mut root.original,
                &mut native.final_header,
                self.opening.current_cutoff_v1()?,
                DeadlineStreamDirectionV1::Read,
            )?;
            let announced = ResourceCompletionProofDataV2::declared_bytes_v2(&native.final_header)?;
            let demand = RootStartResourceFinalExchangeOriginalV2::receiving_demand_v2(
                root.flight,
                announced,
            )?;
            root.flight
                .host_launch_stage_receiving_v1()?
                .admit_host_final_proof_once_v1(RootContinuationDemandV1::from_demand_v1(demand))?;
            let mut exchange = Box::new(RootStartResourceFinalExchangeOriginalV2::new(
                &self.opening,
            )?);
            let returned = exchange.run_once_v2(&self.opening, native, announced, root, policy);
            native.final_exchange = Some(exchange);
            returned?;
            Ok(())
        })());
        self.select_failure(true);
        if !matches!(self.final_result, Some(Ok(()))) || self.failure().is_some() {
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        Ok(())
    }

    pub(crate) fn require_final_complete_v2(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.closed
            || self.failure().is_some()
            || !matches!(self.final_result, Some(Ok(())))
            || self.prelude.original.negative_disposition_entered_v1()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.native
            .as_ref()
            .and_then(|native| native.final_exchange.as_ref())
            .ok_or(NormalRootStartupErrorV1::Service)?
            .require_complete_v2()
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    /// Executes all entered negative posts and same-socket disposition once.
    ///
    /// # Errors
    /// Retains the actual first cause and later debt; failed owners are never disposed.
    pub fn finish_negative_once_v2(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.finish_negative_inner();
        self.negative_disposition
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(|_| ())
            .ok_or(NormalRootStartupErrorV1::Service)
    }

    fn finish_negative_inner(&mut self) {
        if self.negative_disposition.is_some() {
            return;
        }
        let root = &mut self.prelude.original;
        let _owed = root.native.finish_opening_if_owed_v1();
        if let Some(native) = self.native.as_mut() {
            native.finish_posts_once_v2(root.flight);
        }
        let already = self
            .native
            .as_ref()
            .and_then(|native| native.final_exchange.as_ref())
            .is_some_and(|exchange| exchange.peer_post_entered_v2());
        if !already {
            self.negative = Some(
                root.flight
                    .finish_host_launch_controller_peer_posts_once_v1(),
            );
        }
        self.negative_disposition = Some(root.finish_negative_once_v1());
    }

    /// Transfers complete work to the same Root purpose's native upper finisher.
    ///
    /// # Errors
    /// Retains the whole owner through any upper End, post or disposal refusal.
    pub fn finish_positive_once_v2(self) -> Result<(), NormalRootStartupErrorV1> {
        let (work, flight) = match self.into_completed_dispatch_v2() {
            Ok(value) => value,
            Err(mut original) => {
                let _owed = original.finish_negative_once_v2();
                std::process::abort();
            }
        };
        flight.finish_start_resource_dispatch_once_v2(work)
    }

    fn select_failure(&mut self, final_turn: bool) {
        if self.first.is_some() {
            return;
        }
        let failed = if final_turn {
            matches!(self.final_result, Some(Err(_)))
        } else {
            matches!(self.unsigned, Some(Err(_)))
        };
        if !failed {
            return;
        }
        self.first = Some(if self.opening.failure().is_some() {
            First::Opening
        } else if self
            .native
            .as_ref()
            .is_some_and(|native| native.failure().is_some())
        {
            First::Native(
                self.native
                    .as_ref()
                    .map_or(Phase::Opening, |native| native.phase),
            )
        } else if self.prelude.original.flight.failure().is_some() {
            First::Financial
        } else {
            First::Body(final_turn)
        });
    }

    /// Borrows the actual selected cause without decoding, IO or retry.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(First::Opening) => self.opening.failure(),
            Some(First::Native(phase)) => self
                .native
                .as_ref()?
                .phase_failure_v2(phase)
                .or_else(|| self.native.as_ref()?.clock.as_ref()?.failure()),
            Some(First::Financial) => self.prelude.original.flight.failure(),
            Some(First::Body(false)) => self
                .unsigned
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            Some(First::Body(true)) => self
                .final_result
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            None => None,
        };
        self.prelude
            .original
            .native
            .failure_before_v1()
            .or_else(|| self.peer.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or(selected)
            .or_else(|| self.prelude.original.native.failure_after_v1())
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| {
                self.negative
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.negative_disposition
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}
