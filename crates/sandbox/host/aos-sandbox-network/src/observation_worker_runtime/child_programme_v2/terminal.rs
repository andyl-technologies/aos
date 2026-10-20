//! Sends actual O result/negative records while their genuine originals live.
//!
//! ACK is the existing finite Source-only custody disposition, shared by normal
//! and negative handback. A queued positive result never overrides a failed
//! post: the child must exit nonzero, and the parent must join actual native
//! successful worker exit plus UnitResult before treating that result positive.

use super::*;
use crate::kernel_reader::observation_helpers_v2::ReadFrontierOriginalV2;
use crate::observation_worker_runtime::PreparedNetworkObservationV1;
use crate::observation_worker_runtime::read_admission_v2::NetworkObserverReadLoanV2;
use crate::worker_process::NetworkWorkerNegativeV2;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorWorkerNativeSendAttemptV1;
use aos_sandbox_linux::seqpacket::{NetworkWorkerRecordKindV4, RecordBindingError, SeqpacketError};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the observer's original terminal send is closed")]
pub(super) struct TerminalClosedV2;

#[derive(Clone, Copy)]
enum First {
    Order,
    Before,
    Cutoff,
    Send,
    NativePost,
    Binding,
    After,
    NegativeBefore,
    NegativeSend,
    NegativeNativePost,
    NegativeBinding,
    NegativeAfter,
    Panic,
}

/// Retains each actual send/clock/Source prefix through native ACK and exit.
pub(super) struct ObserverTerminalOriginalV2 {
    entered: bool,
    positive_attempted: bool,
    negative_attempted: bool,
    first: Option<First>,
    before: ReadFrontierOriginalV2,
    before_result: Option<Result<(), crate::kernel_reader::NetworkKernelReaderError>>,
    cutoff: Option<aos_sandbox_linux::seqpacket::NetworkWorkerNativeCutoffV4>,
    payload: Option<[u8; 212]>,
    send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    native_post: Option<aos_sandbox_linux::Error>,
    binding: Option<Result<(), RecordBindingError>>,
    after: ReadFrontierOriginalV2,
    after_result: Option<Result<(), crate::kernel_reader::NetworkKernelReaderError>>,
    negative_before: NetworkChildSourceRecordOriginalV2,
    negative_before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    negative_payload: Option<[u8; 160]>,
    negative_send: Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
    negative_native_post: Option<aos_sandbox_linux::Error>,
    negative_binding: Option<Result<(), RecordBindingError>>,
    negative_after: NetworkChildSourceRecordOriginalV2,
    negative_after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
}

impl ObserverTerminalOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            positive_attempted: false,
            negative_attempted: false,
            first: None,
            before: ReadFrontierOriginalV2::new(),
            before_result: None,
            cutoff: None,
            payload: None,
            send: None,
            native_post: None,
            binding: None,
            after: ReadFrontierOriginalV2::new(),
            after_result: None,
            negative_before: NetworkChildSourceRecordOriginalV2::new(),
            negative_before_result: None,
            negative_payload: None,
            negative_send: None,
            negative_native_post: None,
            negative_binding: None,
            negative_after: NetworkChildSourceRecordOriginalV2::new(),
            negative_after_result: None,
        }
    }

    pub(super) fn send_positive_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        read: &NetworkObserverReadLoanV2<'_, '_>,
        response: PreparedNetworkObservationV1,
    ) -> Result<(), TerminalClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(TerminalClosedV2);
        }
        self.entered = true;
        self.before_result = Some(self.before.observe(read, source));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first = Some(First::Before);
        }
        self.cutoff = self.before.native_cutoff_data_v2(read);
        if self.cutoff.is_none() {
            self.first.get_or_insert(First::Cutoff);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                self.payload = Some(super::super::encode_response(response));
                let Some(payload) = self.payload.as_ref() else {
                    return;
                };
                self.positive_attempted = true;
                let (send, post) = socket.send_network_worker_child_record_retaining_v3(
                    NetworkWorkerRecordKindV4::ObservationResult,
                    payload,
                    &[],
                    self.cutoff,
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
            self.first.get_or_insert(First::Panic);
        }
        // Sending may already have queued the result; an owed post failure
        // cannot retract it. Native parent successful-exit join is mandatory.
        self.after_result = Some(self.after.observe(read, source));
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            Err(TerminalClosedV2)
        } else {
            Ok(())
        }
    }

    /// Sends one negative only if no positive native send was ever entered.
    /// Once positive delivery is possible, a failed post instead requires
    /// owed ACK containment followed by actual nonzero worker exit.
    pub(super) fn send_negative_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        negative: NetworkWorkerNegativeV2,
    ) -> Result<(), TerminalClosedV2> {
        if self.positive_attempted || self.negative_attempted {
            return Err(TerminalClosedV2);
        }
        self.negative_attempted = true;
        self.negative_payload = Some(negative.encode());
        self.negative_before_result =
            Some(source.require_owed_netd_peer_once_v2(socket, &mut self.negative_before));
        if !matches!(self.negative_before_result, Some(Ok(()))) {
            self.first.get_or_insert(First::NegativeBefore);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if matches!(self.negative_before_result, Some(Ok(()))) {
                let Some(payload) = self.negative_payload.as_ref() else {
                    return;
                };
                let (send, post) = socket.send_network_worker_child_record_retaining_v3(
                    NetworkWorkerRecordKindV4::PreparationTerminalV2,
                    payload,
                    &[],
                    None,
                );
                self.negative_send = Some(send);
                self.negative_native_post = post;
                if !matches!(self.negative_send, Some(Ok(ref receipt)) if receipt.is_sent()) {
                    self.first.get_or_insert(First::NegativeSend);
                }
                if self.negative_native_post.is_some() {
                    self.first.get_or_insert(First::NegativeNativePost);
                }
                if let Some(Ok(receipt)) = self.negative_send.as_ref() {
                    self.negative_binding = Some(receipt.require_same_socket(socket));
                    if !matches!(self.negative_binding, Some(Ok(()))) {
                        self.first.get_or_insert(First::NegativeBinding);
                    }
                }
            }
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Panic);
        }
        self.negative_after_result =
            Some(source.require_owed_netd_peer_once_v2(socket, &mut self.negative_after));
        if !matches!(self.negative_after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::NegativeAfter);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if matches!(self.negative_send, Some(Ok(ref receipt)) if receipt.is_sent())
            && self.negative_native_post.is_none()
            && matches!(self.negative_binding, Some(Ok(())))
            && matches!(self.negative_before_result, Some(Ok(())))
            && matches!(self.negative_after_result, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(TerminalClosedV2)
        }
    }

    pub(super) fn positive_native_send_was_entered_v2(&self) -> bool {
        self.positive_attempted
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            First::Before => self.before.failure(),
            First::After => self.after.failure(),
            First::Send => send_failure(&self.send),
            First::NativePost => self.native_post.as_ref().map(|error| error as _),
            First::Binding => error(&self.binding),
            First::NegativeBefore => self.negative_before.failure(),
            First::NegativeSend => send_failure(&self.negative_send),
            First::NegativeNativePost => self.negative_native_post.as_ref().map(|error| error as _),
            First::NegativeBinding => error(&self.negative_binding),
            First::NegativeAfter => self.negative_after.failure(),
            First::Order | First::Cutoff | First::Panic => None,
        };
        cause.or(Some(&TerminalClosedV2))
    }
}

fn send_failure(
    value: &Option<Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>>,
) -> Option<&(dyn Error + 'static)> {
    match value.as_ref()? {
        Ok(receipt) => receipt.failure(),
        Err(error) => Some(error),
    }
}

/// Prices result/negative sends; the SAME finite custody port prices ACK.
pub(crate) fn observer_terminal_send_obligations_data_v2() -> Option<ResourceVector> {
    let frontier = ReadFrontierOriginalV2::receiving_obligations_data_v2()?;
    let identity = NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?;
    let bytes = std::mem::size_of::<ObserverTerminalOriginalV2>()
        .checked_mul(2)?
        .checked_add(
            DescriptorSubjectSocket::network_worker_child_send_obligations_v3()?.checked_mul(2)?,
        )?;
    ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .checked_add(frontier)
        .ok()?
        .checked_add(frontier)
        .ok()?
        .checked_add(identity)
        .ok()?
        .checked_add(identity)
        .ok()
}
