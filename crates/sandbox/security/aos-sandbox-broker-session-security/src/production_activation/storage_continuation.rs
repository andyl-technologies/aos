//! Shared retained fixed Storage acceptance before or between genuine Sessions.
//!
//! Existing Journal/floor/endpoint stay resident on continuation. Only a native poll zero
//! with no socket adoption and positive independent original posts is an idle
//! disposition. Every accepted or ambiguous original has one retained owner.

use super::*;
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketAdmissionErrorV1, SeqpacketSocket};

#[derive(Clone, Copy)]
enum StorageAcceptanceOriginalV1<'journal> {
    Initial,
    Retained(&'journal aos_sandbox_controller_domain::Journal),
}

#[derive(Clone, Copy)]
enum Failure {
    Owner(usize),
    Preparation,
    Native(usize),
    Listener(usize),
    Path(usize),
    Poll,
    Accept,
}

pub(crate) struct StorageRetainedSocketAcceptanceV1 {
    owner: [Option<crate::recovery::RetainedStorageOwnerPostV1>; 2],
    native: [Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>; 2],
    post_preparation: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    listener: [Option<Result<(), SeqpacketError>>; 2],
    path: [Option<Result<(), ProductionBrokerSessionActivationErrorV1>>; 2],
    poll: Option<Result<(), ProductionBrokerSessionActivationErrorV1>>,
    native_poll: Option<Result<usize, rustix::io::Errno>>,
    accepted: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    first: Option<Failure>,
    entered: bool,
    idle: bool,
}

impl StorageRetainedSocketAcceptanceV1 {
    pub(crate) fn new() -> Self {
        Self {
            owner: [None, None],
            native: [None, None],
            post_preparation: None,
            listener: [None, None],
            path: [None, None],
            poll: None,
            native_poll: None,
            accepted: None,
            first: None,
            entered: false,
            idle: false,
        }
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.idle
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Owner(index) => self.owner[index].as_ref()?.failure(),
            Failure::Preparation => self.post_preparation.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Native(index) => self.native[index].as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
            Failure::Listener(index) => self.listener[index].as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
            Failure::Path(index) => self.path[index].as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
            Failure::Poll => self.native_poll.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error)
                .or_else(|| self.poll.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error)),
            Failure::Accept => self.accepted.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
        }
    }

    pub(crate) fn observe_owner(
        &mut self,
        owner: &mut crate::recovery::ProtectedBrokerSessionOwnerV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        index: usize,
    ) {
        self.owner[index] = Some(owner.observe_retained_storage_owner_receiving_v3(Some(receiving)));
        if self.owner[index].as_ref().is_some_and(|post| post.failure().is_some()) {
            self.first.get_or_insert(Failure::Owner(index));
        }
    }

    pub(crate) fn take_socket(&mut self) -> Option<SeqpacketSocket> {
        if self.first.is_some() || self.idle {
            return None;
        }
        match self.accepted.take() {
            Some(Ok(socket)) => Some(socket),
            Some(error) => {
                self.accepted = Some(error);
                None
            }
            None => None,
        }
    }

    fn observe(
        &mut self,
        fixed: &FixedListenerV1,
        original: StorageAcceptanceOriginalV1<'_>,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        index: usize,
    ) {
        self.native[index] = Some(match (original, index) {
            (StorageAcceptanceOriginalV1::Initial, 1) => receiving.finish_initial_observation_post_v1(),
            (StorageAcceptanceOriginalV1::Initial, _) => receiving.require_session_fixed_current_v1(),
            (StorageAcceptanceOriginalV1::Retained(journal), _) => receiving.require_retained_session_journal_v1(journal),
        });
        if !matches!(self.native[index], Some(Ok(()))) { self.first.get_or_insert(Failure::Native(index)); }
        self.listener[index] = Some(fixed.listener.validate_current());
        if !matches!(self.listener[index], Some(Ok(()))) { self.first.get_or_insert(Failure::Listener(index)); }
        self.path[index] = Some(require_storage_listener_path(&fixed.listener));
        if !matches!(self.path[index], Some(Ok(()))) { self.first.get_or_insert(Failure::Path(index)); }
    }
}

impl ProductionBrokerSessionActivationV1 {
    pub(crate) fn accept_storage_continuation_socket_v1(
        &mut self,
        journal: &aos_sandbox_controller_domain::Journal,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
        retained: &mut StorageRetainedSocketAcceptanceV1,
    ) {
        Self::accept_storage_socket_inner_v1(
            &mut self.listeners, StorageAcceptanceOriginalV1::Retained(journal), receiving, deadline, retained,
        )
    }

    pub(super) fn accept_storage_initial_socket_v1(
        listeners: &mut [FixedListenerV1],
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
        retained: &mut StorageRetainedSocketAcceptanceV1,
    ) {
        Self::accept_storage_socket_inner_v1(listeners, StorageAcceptanceOriginalV1::Initial, receiving, deadline, retained)
    }

    fn accept_storage_socket_inner_v1(
        listeners: &mut [FixedListenerV1],
        original: StorageAcceptanceOriginalV1<'_>,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
        retained: &mut StorageRetainedSocketAcceptanceV1,
    ) {
        if retained.entered {
            return;
        }
        retained.entered = true;
        if !matches!(&*listeners, [fixed]
            if fixed.endpoint == ProtectedBrokerSessionFixedEndpointV1::StorageBroker)
        {
            retained.path[0] = Some(Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "retained Storage Session requires its same fixed listener",
            )));
            retained.first = Some(Failure::Path(0));
            return;
        }
        loop {
            if matches!(original, StorageAcceptanceOriginalV1::Initial) {
                retained.post_preparation = Some(receiving.arm_initial_observation_post_v1());
                if !matches!(retained.post_preparation, Some(Ok(()))) {
                    retained.first = Some(Failure::Preparation);
                    return;
                }
            }
            retained.observe(&listeners[0], original, receiving, 0);
            if retained.first.is_some() {
                // An entered initial observation owes its already paid after
                // sample even when the before gate closed ordinary admission.
                if matches!(original, StorageAcceptanceOriginalV1::Initial) {
                    retained.observe(&listeners[0], original, receiving, 1);
                }
                return;
            }
            retained.poll = Some(wait_fixed_listeners_until_ready_v1(listeners, deadline, Some(&mut retained.native_poll)));
            let zero = matches!(retained.native_poll, Some(Ok(0)));
            if !matches!(retained.poll, Some(Ok(()))) && !zero {
                retained.first = Some(Failure::Poll);
            }
            if matches!(retained.poll, Some(Ok(()))) {
                retained.accepted = Some(listeners[0].listener.accept_retaining());
                if let Some(Err(error)) = &retained.accepted {
                    if !matches!(error.cause(), SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                        || error.retains_descriptor()
                    {
                        retained.first = Some(Failure::Accept);
                    }
                }
            }
            // These posts execute after poll/accept errors too. The exact
            // accepted error or native errno keeps first-cause priority.
            retained.observe(&listeners[0], original, receiving, 1);
            if retained.first.is_some() {
                return;
            }
            if zero {
                // No accept was attempted and no HELLO exists. Required PID1
                // currentness flights have their own real paid/settled lane;
                // dispose only these successful no-acquisition observations
                // before a fresh finite transport accept interval.
                retained.idle = true;
                return;
            }
            if matches!(retained.accepted, Some(Ok(_))) {
                return;
            }
            // Only actual no-acquisition EAGAIN/EINTR with all posts positive
            // reaches another poll. The same finite cutoff is unchanged.
            retained.accepted = None;
            retained.native_poll = None;
            retained.poll = None;
        }
    }
}
