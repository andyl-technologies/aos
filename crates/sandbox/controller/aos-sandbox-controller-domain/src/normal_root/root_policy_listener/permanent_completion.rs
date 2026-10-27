//! Runs the prepaid permanent response after transient financial disposition.
//!
//! Its fixed plan is comparison DATA. The private serving finisher enters only
//! after actual transient disposal; every native destination and traffic byte
//! is admitted on the same permanent Root original before the body begins.

use super::*;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootPrearmedHistoryServicePostV1};
use aos_linux_descriptors::unix_stream::UnixStreamOriginalCurrentnessV1;
use aos_sandbox_protocol::host_execution_no_apply::closed_controller::ControllerCreateFailureAckDataV2;
use aos_sandbox_protocol::root_policy_completion::{
    delete_root_positive_completion_bytes_v2, execution_no_apply_positive_completion_bytes_v2,
};

/// Carries a passive fixed response and its unchanged request deadline.
pub(crate) struct RootPolicyPositiveCompletionPlanV2 {
    bytes: [u8; 48],
    cutoff: u64,
}

impl RootPolicyPositiveCompletionPlanV2 {
    pub(crate) fn stop_cleanup_data_v1(query: [u8; 32], decision: [u8; 32], terminal: [u8; 32], cutoff: u64) -> Self {
        Self { bytes: aos_sandbox_protocol::root_policy_completion::stop_cleanup_positive_completion_bytes_v1(
            query, decision, terminal), cutoff }
    }
    pub(crate) fn delete_data_v2(ack: [u8; 32], cutoff: u64) -> Self {
        Self {
            bytes: delete_root_positive_completion_bytes_v2(ack),
            cutoff,
        }
    }

    pub(crate) fn execution_no_apply_data_v2(
        query: [u8; 32],
        floor: [u8; 32],
        ack: ControllerCreateFailureAckDataV2,
        cutoff: u64,
    ) -> Self {
        Self {
            bytes: execution_no_apply_positive_completion_bytes_v2(query, floor, ack),
            cutoff,
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Funding,
    Arm(usize),
    Before,
    StreamBefore,
    Write,
    StreamAfter,
    After,
    Reentry,
}

#[derive(Default)]
pub(super) struct RootPermanentCompletionOriginalV2 {
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    posts: [Option<Result<RootPrearmedHistoryServicePostV1, RootObservationErrorV1>>; 2],
    observed: [Option<Result<(), RootObservationErrorV1>>; 2],
    stream_before: UnixStreamOriginalCurrentnessV1,
    stream_before_result: Option<aos_linux_descriptors::Result<()>>,
    stream_after: UnixStreamOriginalCurrentnessV1,
    stream_after_result: Option<aos_linux_descriptors::Result<()>>,
    plan: Option<RootPolicyPositiveCompletionPlanV2>,
    sender: FixedDeadlineStreamIoV1<48>,
    sent: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    >,
    entered: bool,
    first: Option<First>,
}

impl RootPermanentCompletionOriginalV2 {
    pub(super) fn receiving_demand_v2() -> Option<ResourceVector> {
        let sample = RootPrearmedHistoryServicePostV1::demand_v1()?;
        let stream = UnixStreamOriginalCurrentnessV1::receiving_demand_v1()?;
        let stream = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(stream.0).ok()?)
            .with(D::MetadataEntries, u64::try_from(stream.1).ok()?)
            .with(D::OpenFiles, u64::try_from(stream.2).ok()?);
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?)?;
        sample
            .checked_add(sample)
            .ok()?
            .checked_add(stream).ok()?
            .checked_add(stream).ok()?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                    .with(D::NetworkBytes, 48)
                    .with(D::OutputBytes, 48),
            )
            .ok()
    }

    // Self is already parked on the listener before either native arm.
    pub(super) fn arm_before_body_once_v2(
        &mut self,
        original: &mut crate::controller_resource_reservation::RootReceivingOriginalV1,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.funding.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.funding = Some(original.prepay_policy_completion_tail_once_v2());
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(NormalRootStartupErrorV1::Service);
        }

        for index in 0..2 {
            self.posts[index] = Some(original.arm_policy_completion_tail_post_v2(startup));
            if !matches!(self.posts[index], Some(Ok(_))) {
                self.first = Some(First::Arm(index));
                return Err(NormalRootStartupErrorV1::Service);
            }
        }
        Ok(())
    }

    pub(super) fn require_armed_empty_v2(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.plan.is_some()
            || self.entered
            || self.first.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || self.posts.iter().any(|post| !matches!(post, Some(Ok(_))))
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        Ok(())
    }

    pub(super) fn install_completed_plan_v2(&mut self, plan: RootPolicyPositiveCompletionPlanV2) {
        if self.require_armed_empty_v2().is_err() {
            std::process::abort();
        }
        self.plan = Some(plan);
    }

    // The sole caller follows RootPolicyFlightDisposalV1 completion. No public
    // entry, borrowed D owner or new debit survives to this native programme.
    pub(super) fn send_after_positive_disposition_once_v2(
        &mut self,
        original: &mut crate::controller_resource_reservation::RootReceivingOriginalV1,
        startup: &ProductionNormalRootStartupV1,
        native: &mut RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.entered || self.first.is_some() || self.plan.is_none() {
            self.first.get_or_insert(First::Reentry);
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.entered = true;

        self.observed[0] = Some(
            original.observe_policy_completion_tail_post_v2(
                startup,
                self.posts[0]
                    .as_mut()
                    .and_then(|post| post.as_mut().ok())
                    .ok_or(NormalRootStartupErrorV1::Service)?,
            ),
        );
        if !matches!(self.observed[0], Some(Ok(()))) {
            self.first = Some(First::Before);
        }
        if self.first.is_none() {
            self.stream_before_result =
                Some(native.revalidate_original_retaining_v1(&mut self.stream_before));
            if !matches!(self.stream_before_result, Some(Ok(()))) {
                self.first = Some(First::StreamBefore);
            }
        }
        if self.first.is_none() {
            if let Some(plan) = self.plan.as_mut() {
                self.sent = Some(self.sender.run_once(
                    native,
                    &mut plan.bytes,
                    plan.cutoff,
                    DeadlineStreamDirectionV1::Write,
                ));
            }
            if !matches!(self.sent, Some(Ok(()))) || !self.sender.completed_exact() {
                self.first = Some(First::Write);
            }
        }

        // Both prepaid afters remain owed after any primary. No healthy D gate
        // or fresh debit is used by these independent native observations.
        self.stream_after_result =
            Some(native.revalidate_original_retaining_v1(&mut self.stream_after));
        if !matches!(self.stream_after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::StreamAfter);
        }
        self.observed[1] = Some(
            original.observe_policy_completion_tail_post_v2(
                startup,
                self.posts[1]
                    .as_mut()
                    .and_then(|post| post.as_mut().ok())
                    .ok_or(NormalRootStartupErrorV1::Service)?,
            ),
        );
        if !matches!(self.observed[1], Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if self.first.is_some() {
            Err(NormalRootStartupErrorV1::Service)
        } else {
            Ok(())
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Funding => self
                .funding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Arm(index) => self.posts[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Before | First::After => {
                let index = if matches!(self.first, Some(First::Before)) {
                    0
                } else {
                    1
                };
                self.posts[index]
                    .as_ref()
                    .and_then(|post| post.as_ref().ok())
                    .and_then(|post| post.failure())
                    .or_else(|| {
                        self.observed[index]
                            .as_ref()?
                            .as_ref()
                            .err()
                            .map(|cause| cause as _)
                    })
            }
            First::StreamBefore => self.stream_before.failure(),
            First::StreamAfter => self.stream_after.failure(),
            First::Write => self
                .sender
                .failure()
                .or_else(|| self.sent.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Reentry => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unarmed_comparison_plan_cannot_enter_permanent_native_programme() {
        let owner = RootPermanentCompletionOriginalV2::default();
        assert!(owner.require_armed_empty_v2().is_err());
        let priced = RootPermanentCompletionOriginalV2::receiving_demand_v2().unwrap();
        let native = RootPrearmedHistoryServicePostV1::demand_v1().unwrap();
        let stream = UnixStreamOriginalCurrentnessV1::receiving_demand_v1().unwrap();
        assert!(priced.get(D::MemoryBytes) >= native.get(D::MemoryBytes) * 2 + stream.0 as u64 * 2);
        assert!(priced.get(D::OpenFiles) >= native.get(D::OpenFiles) * 2);
        assert!(priced.get(D::NetworkBytes) >= native.get(D::NetworkBytes) * 2 + 48);
        assert!(priced.get(D::OutputBytes) >= native.get(D::OutputBytes) * 2 + 48);
    }

    #[test]
    fn pre_disposition_ack_followed_by_process_style_eof_lacks_confirmation() {
        use std::io::Write as _;

        let peer = aos_linux_descriptors::pidfd::PidFd::open(
            std::num::NonZeroU32::new(std::process::id()).unwrap(),
        )
        .unwrap();
        let acknowledgement = [7; 32];
        let expected = delete_root_positive_completion_bytes_v2(acknowledgement);

        for prefix in [0, expected.len() - 1] {
            let (mut root, mut controller) = UnixStream::pair().unwrap();
            root.write_all(&acknowledgement).unwrap();
            root.write_all(&expected[..prefix]).unwrap();
            drop(root);
            let mut historical_ack = [0; 32];
            let mut ack_io = FixedDeadlineStreamIoV1::<32>::default();
            ack_io
                .run_once(
                    &mut controller,
                    &mut historical_ack,
                    u64::MAX,
                    DeadlineStreamDirectionV1::Read,
                )
                .unwrap();
            let mut response = [0; 48];
            let mut response_io = FixedDeadlineStreamIoV1::<48>::default();

            let received = response_io.run_once(
                &mut controller,
                &mut response,
                u64::MAX,
                DeadlineStreamDirectionV1::Read,
            );

            assert_eq!(historical_ack, acknowledgement);
            assert!(ack_io.completed_exact());
            assert!(peer.is_alive().unwrap());
            assert!(received.is_err());
            assert!(!response_io.completed_exact());
            assert!(response_io.failure().is_some());
            assert_eq!(&response[..prefix], &expected[..prefix]);
            assert_ne!(response, expected);
        }
    }
}
