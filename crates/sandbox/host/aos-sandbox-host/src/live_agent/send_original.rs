//! Owns one reached Agent native write and its final typed denial gate.
//!
//! Handshake and execution senders share this mechanical destination. It
//! carries no launch, execution, Capture or retry permission.

use std::error::Error;
use super::HostAgentLiveErrorV1;

pub(in crate::live_agent) struct AgentSendAttemptV4 {
    pub(in crate::live_agent) native: aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1,
    pub(in crate::live_agent) guard: Option<HostAgentLiveErrorV1>,
}

impl AgentSendAttemptV4 {
    pub(in crate::live_agent) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // The callback follows a successful leading carrier observation.
        self.guard.as_ref().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.native.failure())
    }
}
