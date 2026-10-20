//! Sends P READY/result/negative DATA through the one retained native sender.
//!
//! Bootstrap requires genuine live Source. Positive result additionally uses
//! the original completed63/9 authority and unchanged D. Negative handback is
//! independently prepaid native custody. A failed post after possible positive
//! delivery requires nonzero exit, never a contradictory replacement result.

use super::signed_admission::PreparationClockOriginalV2;
use super::*;
use crate::lifecycle_worker_protocol::NetworkLifecycleExecutionAuthorizationV1;
use crate::worker_process::{NetworkWorkerNegativeV2, NetworkWorkerReadyV1, NetworkWorkerResultV1};
use crate::worker_protocol::{NetworkMutationAuthorizationV1, NetworkWorkerProtocolError};
use aos_sandbox_broker::BrokerEffectIntentV1;
use aos_sandbox_model::LocalLeaseRecord;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorWorkerNativeSendAttemptV1;
use aos_sandbox_linux::seqpacket::{
    NetworkWorkerNativeCutoffV4, NetworkWorkerRecordKindV4, RecordBindingError, SeqpacketError,
};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original P native send retained its refusal")]
pub(super) struct PreparationSendClosedV2;

/// Borrows the same completed operation; it creates no new effect permission.
pub(super) enum PreparationResultAuthorityV2<'held> {
    Prepare(&'held NetworkMutationAuthorizationV1),
    Destroy(&'held NetworkLifecycleExecutionAuthorizationV1, &'held [u8]),
}

impl PreparationResultAuthorityV2<'_> {
    fn originals(&self) -> Option<(&BrokerEffectIntentV1, &LocalLeaseRecord)> {
        match self {
            Self::Prepare(authority) => Some((
                authority.original_effect_v2(),
                authority.original_local_lease_v2(),
            )),
            Self::Destroy(authority, _) => authority.completed_result_inputs_v2(),
        }
    }

    fn require_current(
        &self,
        authority: &NetworkAuthorityV1,
        clock: &mut PreparationClockOriginalV2,
        boot: [u8; 16],
    ) -> Result<(), NetworkWorkerProtocolError> {
        match self {
            Self::Prepare(operation) => operation
                .require_current_before_helper_v2(authority, &mut || clock.observe_once_v2(boot)),
            Self::Destroy(operation, fence) => operation.require_current_before_result_v2(
                authority,
                &mut || Ok(fence.to_vec()),
                &mut || clock.observe_once_v2(boot),
            ),
        }
    }

    fn cutoff(&self, clock: &PreparationClockOriginalV2) -> Option<NetworkWorkerNativeCutoffV4> {
        let sample = clock.sample_data_v2()?;
        let (effect, lease) = self.originals()?;
        Some(NetworkWorkerNativeCutoffV4::new(
            sample.boottime_nanoseconds(),
            sample.wall_seconds(),
            effect
                .effect_deadline_boottime_nanoseconds()
                .min(lease.fail_stop_boottime_nanoseconds()),
            Some(
                effect
                    .plan_expires_seconds()
                    .min(effect.authority_expires_seconds()),
            ),
        ))
    }

    fn remaining(&self, clock: &PreparationClockOriginalV2) -> Option<rustix::event::Timespec> {
        let sample = clock.sample_data_v2()?;
        let wall = clock.realtime_data_v2()?;
        let (effect, lease) = self.originals()?;
        let deadline = effect
            .effect_deadline_boottime_nanoseconds()
            .min(lease.fail_stop_boottime_nanoseconds());
        let expiry = effect
            .plan_expires_seconds()
            .min(effect.authority_expires_seconds());
        let boot = deadline.checked_sub(sample.boottime_nanoseconds())?;
        let wall = u64::try_from(expiry.checked_sub(wall.tv_sec)?)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_sub(u64::try_from(wall.tv_nsec).ok()?)?;
        let remaining = boot.min(wall);
        if remaining == 0 {
            return None;
        }
        Some(rustix::event::Timespec {
            tv_sec: i64::try_from(remaining / 1_000_000_000).ok()?,
            tv_nsec: i64::try_from(remaining % 1_000_000_000).ok()?,
        })
    }
}

#[derive(Clone, Copy)]
enum First {
    Order,
    Shape,
    ClockBefore,
    SourceBefore,
    Send,
    NativePost,
    Binding,
    ClockAfter,
    SourceAfter,
}

pub(super) struct PreparationPositiveSendOriginalV2 {
    entered: bool,
    native_entered: bool,
    first: Option<First>,
    ready: Option<Result<NetworkWorkerReadyV1, crate::worker_process::NetworkWorkerProcessError>>,
    payload: Option<Result<Vec<u8>, crate::worker_process::NetworkWorkerProcessError>>,
    before: NetworkChildSourceProbeOriginalV2,
    before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    clock_before: PreparationClockOriginalV2,
    current_before: Option<Result<(), NetworkWorkerProtocolError>>,
    wait_before: Option<rustix::event::Timespec>,
    send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    native_post: Option<aos_sandbox_linux::Error>,
    binding: Option<Result<(), RecordBindingError>>,
    clock_after: PreparationClockOriginalV2,
    current_after: Option<Result<(), NetworkWorkerProtocolError>>,
    wait_after: Option<rustix::event::Timespec>,
    after: NetworkChildSourceProbeOriginalV2,
    after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
}

impl PreparationPositiveSendOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            native_entered: false,
            first: None,
            ready: None,
            payload: None,
            before: NetworkChildSourceProbeOriginalV2::new(),
            before_result: None,
            clock_before: PreparationClockOriginalV2::new(),
            current_before: None,
            wait_before: None,
            send: None,
            native_post: None,
            binding: None,
            clock_after: PreparationClockOriginalV2::new(),
            current_after: None,
            wait_after: None,
            after: NetworkChildSourceProbeOriginalV2::new(),
            after_result: None,
        }
    }

    pub(super) fn send_ready_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        cgroup: &str,
        namespace: &NamespaceFd,
    ) -> Result<(), PreparationSendClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(PreparationSendClosedV2);
        }
        self.ready = Some(NetworkWorkerReadyV1::new_receiving_v4(
            cgroup.to_owned(),
            namespace.identity(),
        ));
        self.payload = self
            .ready
            .as_ref()
            .and_then(|ready| ready.as_ref().ok())
            .map(NetworkWorkerReadyV1::encode);
        self.run_once_v2(
            source,
            socket,
            NetworkWorkerRecordKindV4::PreparationReady,
            &[namespace.as_fd()],
            None,
        )
    }

    pub(super) fn send_result_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        response: NetworkWorkerResultV1,
        authority: &NetworkAuthorityV1,
        original: PreparationResultAuthorityV2<'_>,
    ) -> Result<(), PreparationSendClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(PreparationSendClosedV2);
        }
        self.payload = Some(Ok(response.encode().to_vec()));
        self.run_once_v2(
            source,
            socket,
            NetworkWorkerRecordKindV4::PreparationResult,
            &[],
            Some((authority, original)),
        )
    }

    fn run_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        kind: NetworkWorkerRecordKindV4,
        descriptors: &[std::os::fd::BorrowedFd<'_>],
        authority: Option<(&NetworkAuthorityV1, PreparationResultAuthorityV2<'_>)>,
    ) -> Result<(), PreparationSendClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(PreparationSendClosedV2);
        }
        self.entered = true;
        let boot = source
            .operation_binding_data_v2()
            .map(|binding| binding.boot);
        if let Some((configured, operation)) = authority.as_ref() {
            self.current_before = Some(match boot {
                Some(boot) => operation.require_current(configured, &mut self.clock_before, boot),
                None => Err(NetworkWorkerProtocolError::Authority),
            });
            self.wait_before = operation.remaining(&self.clock_before);
            if !matches!(self.current_before, Some(Ok(()))) || self.wait_before.is_none() {
                self.first = Some(First::ClockBefore);
            }
        }
        if self.first.is_none() {
            self.before_result = Some(
                source.require_live_before_once_v2(&mut self.before, self.wait_before.as_ref()),
            );
            if !matches!(self.before_result, Some(Ok(()))) {
                self.first = Some(First::SourceBefore);
            }
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                let Some(Ok(payload)) = self.payload.as_ref() else {
                    self.first = Some(First::Shape);
                    return;
                };
                let cutoff = authority
                    .as_ref()
                    .and_then(|(_, operation)| operation.cutoff(&self.clock_before));
                self.native_entered = true;
                let (send, post) = socket.send_network_worker_child_record_retaining_v3(
                    kind,
                    payload,
                    descriptors,
                    cutoff,
                );
                self.send = Some(send);
                self.native_post = post;
                if !matches!(self.send, Some(Ok(ref receipt)) if receipt.is_sent()) {
                    self.first = Some(First::Send);
                }
                if self.native_post.is_some() {
                    self.first.get_or_insert(First::NativePost);
                }
                if let Some(Ok(receipt)) = self.send.as_ref() {
                    self.binding = Some(receipt.require_same_socket(socket));
                    if !matches!(self.binding, Some(Ok(()))) {
                        self.first.get_or_insert(First::Binding);
                    }
                }
            }
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Send);
        }
        if let Some((configured, operation)) = authority.as_ref() {
            self.current_after = Some(match boot {
                Some(boot) => operation.require_current(configured, &mut self.clock_after, boot),
                None => Err(NetworkWorkerProtocolError::Authority),
            });
            self.wait_after = operation.remaining(&self.clock_after);
            if !matches!(self.current_after, Some(Ok(()))) || self.wait_after.is_none() {
                self.first.get_or_insert(First::ClockAfter);
            }
        }
        self.after_result = Some(
            if source.operation_binding_data_v2().is_some()
                && (authority.is_none() || self.wait_after.is_some())
            {
                source.require_live_before_once_v2(&mut self.after, self.wait_after.as_ref())
            } else {
                source.observe_owed_native_after_once_v2(&mut self.after)
            },
        );
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::SourceAfter);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            Err(PreparationSendClosedV2)
        } else {
            Ok(())
        }
    }

    pub(super) fn native_entered_v2(&self) -> bool {
        self.native_entered
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            First::ClockBefore => self
                .clock_before
                .failure()
                .or_else(|| failed(&self.current_before)),
            First::ClockAfter => self
                .clock_after
                .failure()
                .or_else(|| failed(&self.current_after)),
            First::SourceBefore => self.before.failure(),
            First::SourceAfter => self.after.failure(),
            First::Shape => failed(&self.ready).or_else(|| failed(&self.payload)),
            First::NativePost => self.native_post.as_ref().map(|cause| cause as _),
            First::Binding => failed(&self.binding),
            First::Send => match self.send.as_ref() {
                Some(Ok(receipt)) => receipt.failure(),
                Some(Err(cause)) => Some(cause as _),
                None => None,
            },
            First::Order => None,
        };
        cause.or(Some(&PreparationSendClosedV2))
    }

    pub(super) fn receiving_obligations_data_v2() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(DescriptorSubjectSocket::network_worker_child_send_obligations_v3()?)?
            .checked_add(2usize.checked_mul(super::super::MAXIMUM_READY_BYTES)?)?;
        let mut demand = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?);
        demand = demand
            .checked_add(NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(2)?)
            .ok()?;
        for _ in 0..2 {
            demand = demand
                .checked_add(PreparationClockOriginalV2::receiving_obligations_data_v2()?)
                .ok()?;
        }
        Some(demand)
    }
}
