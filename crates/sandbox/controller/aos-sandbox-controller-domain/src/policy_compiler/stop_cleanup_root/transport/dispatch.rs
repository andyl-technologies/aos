//! Moves the whole genuine Stop cleanup graph into the existing Root finisher.
//!
//! Every offered owner, including a failed body, uses the finite no-shutdown
//! completion arm. Only actual Stop/final inventory/native posts produce a passive fixed
//! confirmation plan; only the common genuine Dpositive boundary unlocks its
//! permanent-F sender. No Result or decoded packet grants that boundary.

use super::*;
use crate::policy_compiler::root_policy_prelude::{
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1, RootPolicyPreludeOriginalV1,
};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

pub(crate) struct RootStopCleanupDispatchOriginalV1 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    body: Option<Result<(), Cause>>,
    peer_post: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_settled: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootStopCleanupDispatchOriginalV1 {
    fn require_complete(&self) -> Result<&Native, NormalRootStartupErrorV1> {
        if !self.disposition.entered
            || self.disposition.handed_off
            || !matches!(self.peer, Some(Ok(())))
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.peer_post, Some(Ok(())))
            || !matches!(self.peer_settled, Some(Ok(())))
            || self.prelude.failure_before_v1().is_some()
            || self.prelude.failure_after_v1().is_some()
            || self.failure().is_some()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let native = self
            .native
            .as_deref()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        native
            .require_complete()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        Ok(native)
    }

    pub(crate) fn require_same_complete_v1(
        &self,
        original: &RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.require_complete()?;
        original
            .require_same_endpoint_v1(self.original.as_fd())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn completed_confirmation_plan_v2(
        &self,
    ) -> Result<crate::normal_root::RootPolicyPositiveCompletionPlanV2, NormalRootStartupErrorV1>
    {
        let native = self.require_complete()?;
        let (query, decision, terminal, cutoff) = native
            .issuer
            .completion_data_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        if cutoff
            != native
                .opening
                .current_cutoff_v1()
                .map_err(|_| NormalRootStartupErrorV1::Service)?
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        Ok(
            crate::normal_root::RootPolicyPositiveCompletionPlanV2::stop_cleanup_data_v1(
                query, decision, terminal, cutoff,
            ),
        )
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.prelude
            .failure_before_v1()
            .or_else(|| error(&self.peer))
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(|native| native.failure_before())
            })
            .or_else(|| {
                self.native
                    .as_ref()
                    .filter(|native| matches!(native.first, Some(Phase::Opening)))
                    .and_then(|_| self.prelude.failure_after_v1())
            })
            .or_else(|| boxed_error(&self.body))
            .or_else(|| self.prelude.failure_after_v1())
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(|native| native.failure_after())
            })
            .or_else(|| error(&self.peer_post))
            .or_else(|| error(&self.peer_settled))
    }

    // The shared native financial consumer is the sole successful destructor.
    pub(crate) fn complete_upper_disposal_v1(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("the original semantic decision refused")]
    struct OriginalDecision;

    fn work(body: Result<(), Cause>) -> RootStopCleanupDispatchOriginalV1 {
        let (original, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let mut native = Native::new();
        native.first = Some(Phase::Reply);
        native.after_binding = Some(Err(JournalError::ProtectedBoundary));
        RootStopCleanupDispatchOriginalV1 {
            disposition: Default::default(),
            original,
            prelude: Default::default(),
            peer: Some(Ok(())),
            native: Some(Box::new(native)),
            body: Some(body),
            peer_post: Some(Ok(())),
            peer_settled: Some(Ok(())),
        }
    }

    #[test]
    fn retained_semantic_refusal_precedes_the_independently_owed_after() {
        for phase in [Phase::Reply, Phase::Decision, Phase::Final] {
            let mut work = work(Err(Box::new(OriginalDecision)));
            let native = work.native.as_mut().unwrap();
            native.first = Some(phase);
            let sample = RawPairedClockSample::new_untrusted(
                aos_sandbox_model::RawClockProvenance::new_untrusted([1; 16]).unwrap(),
                [2; 16],
                100,
                10_000_000_000,
            )
            .unwrap();
            let mut clock = RootContinuationClockGateV1::new(
                RootContinuationHorizonDataV1::from_original_data_v1(sample, 20_000_000_000)
                    .unwrap(),
            );
            // The comparison owner was healthy at body return. A later
            // independently owed refusal cannot become the primary cause.
            assert!(
                clock
                    .narrow_original_cutoff_data_v2(30_000_000_000)
                    .is_err()
            );
            native.clock = Some(Box::new(clock));
            assert!(!native.clock_failed_in_body);

            assert!(
                work.failure()
                    .unwrap()
                    .downcast_ref::<OriginalDecision>()
                    .is_some()
            );
            assert!(work.native.as_ref().unwrap().failure_after().is_some());
            assert!(work.completed_confirmation_plan_v2().is_err());
        }
    }

    #[test]
    fn successful_comparison_data_cannot_install_a_post_disposal_plan() {
        let mut work = work(Ok(()));
        let native = work.native.as_mut().unwrap();
        native.first = None;
        native.after_binding = Some(Ok(()));
        work.disposition.entered = true;

        // No paid native programme or genuine held flight was constructed.
        // Even superficially positive result slots cannot produce Root48.
        let refused = work.completed_confirmation_plan_v2().is_err();
        work.disposition.handed_off = true;
        assert!(refused);
    }
}

fn boxed_error(value: &Option<Result<(), Cause>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}

impl<'flight, 'listener, 'startup> RootStopCleanupReceivingV1<'flight, 'listener, 'startup> {
    pub(super) fn finish_offered(mut self) -> Result<(), NormalRootStartupErrorV1> {
        let complete = matches!(self.body, Some(Ok(())))
            && matches!(self.peer_post, Some(Ok(())))
            && self
                .native
                .as_deref()
                .is_some_and(|native| native.require_complete().is_ok());
        if complete {
            self.peer_settled = Some(
                self.prelude
                    .original
                    .flight
                    .settle_stop_cleanup_controller_peer_positive_once_v1(),
            );
        }
        let Self {
            prelude,
            peer,
            native,
            body,
            peer_post,
            peer_settled,
        } = self;
        let RootPolicyPreludeOriginalV1 {
            disposition,
            original,
            flight,
            native: prelude,
            ..
        } = prelude.original;
        let work = RootStopCleanupDispatchOriginalV1 {
            disposition,
            original,
            prelude,
            peer,
            native,
            body,
            peer_post,
            peer_settled,
        };
        flight.finish_stop_cleanup_dispatch_once_v1(work)
    }
}
