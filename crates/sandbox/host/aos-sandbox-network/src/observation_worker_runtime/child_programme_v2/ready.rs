//! Emits READY only on the genuine already-paid Source bootstrap programme.
//!
//! READY precedes the original operation D. The actual native cgroup name is
//! correlation DATA; parent custody still requires its held PIDFD and cgroup.

use super::*;
use crate::worker_cgroup_v2::{NetworkWorkerCgroupClosedV2, NetworkWorkerCgroupOriginalV2};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorWorkerNativeSendAttemptV1;
use aos_sandbox_linux::seqpacket::{NetworkWorkerRecordKindV4, RecordBindingError, SeqpacketError};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the observer's original READY send is closed")]
pub(super) struct ReadyClosedV2;

#[derive(Clone, Copy)]
enum First {
    Order,
    Before,
    Cgroup,
    Shape,
    Encode,
    Send,
    NativePost,
    Binding,
    After,
    Panic,
}

pub(super) struct ObserverReadyOriginalV2 {
    entered: bool,
    first: Option<First>,
    before: NetworkChildSourceProbeOriginalV2,
    before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    cgroup: NetworkWorkerCgroupOriginalV2,
    cgroup_result: Option<Result<(), NetworkWorkerCgroupClosedV2>>,
    ready: Option<Result<super::super::ObservationReadyV1, NetworkObservationWorkerError>>,
    payload: Option<Result<Vec<u8>, NetworkObservationWorkerError>>,
    send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    native_post: Option<aos_sandbox_linux::Error>,
    binding: Option<Result<(), RecordBindingError>>,
    after: NetworkChildSourceProbeOriginalV2,
    after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
}

impl ObserverReadyOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            first: None,
            before: NetworkChildSourceProbeOriginalV2::new(),
            before_result: None,
            cgroup: NetworkWorkerCgroupOriginalV2::new(),
            cgroup_result: None,
            ready: None,
            payload: None,
            send: None,
            native_post: None,
            binding: None,
            after: NetworkChildSourceProbeOriginalV2::new(),
            after_result: None,
        }
    }

    pub(super) fn send_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
    ) -> Result<(), ReadyClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(ReadyClosedV2);
        }
        self.entered = true;
        self.before_result = Some(source.require_live_before_once_v2(&mut self.before, None));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first = Some(First::Before);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_some() {
                return;
            }
            self.cgroup_result = Some(self.cgroup.capture_once_v2(source));
            if !matches!(self.cgroup_result, Some(Ok(()))) {
                self.first = Some(First::Cgroup);
                return;
            }
            let Some(path) = self.cgroup.take_completed_once_v2() else {
                self.first = Some(First::Cgroup);
                return;
            };
            self.ready = Some(super::super::ObservationReadyV1::new_receiving_v4(path));
            let Some(Ok(ready)) = self.ready.as_ref() else {
                self.first = Some(First::Shape);
                return;
            };
            self.payload = Some(ready.encode());
            let Some(Ok(payload)) = self.payload.as_ref() else {
                self.first = Some(First::Encode);
                return;
            };
            // No effect D exists yet. Native Source bootstrap and its preissued
            // finite invoice authorize only this READY/custody step.
            let (send, post) = socket.send_network_worker_child_record_retaining_v3(
                NetworkWorkerRecordKindV4::ObservationReady,
                payload,
                &[],
                None,
            );
            self.send = Some(send);
            self.native_post = post;
            if !matches!(self.send,Some(Ok(ref receipt)) if receipt.is_sent()) {
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
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Panic);
        }
        self.after_result = Some(if source.operation_binding_data_v2().is_some() {
            source.require_live_before_once_v2(&mut self.after, None)
        } else {
            source.observe_owed_native_after_once_v2(&mut self.after)
        });
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            Err(ReadyClosedV2)
        } else {
            Ok(())
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            First::Before => self.before.failure(),
            First::Cgroup => self.cgroup.failure(),
            First::Shape => error(&self.ready),
            First::Encode => error(&self.payload),
            First::Send => match self.send.as_ref() {
                Some(Ok(receipt)) => receipt.failure(),
                Some(Err(error)) => Some(error as _),
                None => None,
            },
            First::NativePost => self.native_post.as_ref().map(|error| error as _),
            First::Binding => error(&self.binding),
            First::After => self.after.failure(),
            First::Order | First::Panic => None,
        };
        cause.or(Some(&ReadyClosedV2))
    }
}

/// Prices this same READY owner, its actual native capture, send and Source posts.
pub(crate) fn observer_ready_obligations_data_v2() -> Option<ResourceVector> {
    let bytes = std::mem::size_of::<ObserverReadyOriginalV2>()
        .checked_mul(2)?
        .checked_add(3 * 512 + 528)?
        .checked_add(DescriptorSubjectSocket::network_worker_child_send_obligations_v3()?)?;
    ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .checked_add(NetworkWorkerCgroupOriginalV2::receiving_obligations_data_v2()?)
        .ok()?
        .checked_add(NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(2)?)
        .ok()
}
