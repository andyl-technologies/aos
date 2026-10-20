//! Records the actual native roster after whole Launch acquisition disposal.
//!
//! Completed initial journals, credential readers, SDK collectors and inspection
//! prefixes retire only at the existing authenticated Sent frontier. The real
//! runtime pins and authenticated Agent remain. This private proof changes no
//! grant, capacity, historical highwater or spent traffic.

use super::*;

pub(crate) struct HostLaunchResidentNativeV4 {
    request: ([u8; 16], [u8; 32], [u8; 32]),
    files: usize,
}

pub(super) struct ResidentNativePendingV4 {
    request: ([u8; 16], [u8; 32], [u8; 32]),
    files: usize,
}

impl HostLaunchResidentNativeV4 {
    pub(crate) fn request_identity_v4(&self) -> ([u8; 16], [u8; 32], [u8; 32]) {
        self.request
    }

    pub(crate) fn current_native_files_v4(&self) -> usize {
        self.files
    }
}

impl ResidentNativePendingV4 {
    // All role/alias checks precede physical disposal. This factory borrows the
    // same actual maps and incoming Agent while HostBroker is exclusively held.
    pub(in crate::broker::launch_handoff) fn prepare(
        stage: &HostLaunchOriginalV2,
        pins: &std::collections::BTreeMap<crate::worker::HostRuntimeIdentity, super::super::RetainedRuntimePins>,
        leaders: &std::collections::BTreeMap<crate::worker::HostRuntimeIdentity, crate::worker::PinnedLeader>,
        agent: &crate::live_agent::HostAgentLiveSessionV1,
    ) -> Result<Self> {
        if stage.authenticated_sent || stage.first.is_some() || stage.resident_native.is_some()
            || stage.capture.is_some() || pins.len() != 1 || leaders.len() != 1
            || stage.agent_binding != Some(agent.session_binding())
            || stage.names.iter().flatten().any(|names| !names.is_complete())
            || stage.name_results.iter().flatten().any(|result| !matches!(result, Some(Ok(()))))
        {
            return Err(HostError::Fence("Launch resident native roster is not the actual completed handoff"));
        }
        let (identity, actual) = pins.first_key_value()
            .ok_or(HostError::Fence("actual Launch runtime pins are absent"))?;
        let observed = leaders.get(identity)
            .ok_or(HostError::Fence("actual Launch observed leader is absent"))?;
        if observed.handle() != actual.supervisor.handle() {
            return Err(HostError::Fence("actual Launch supervisor registries differ"));
        }

        // RetainedRuntimePins owns supervisor pidfd1 and payload's pidfd,
        // cgroup, root and four namespace handles7. The observed leader owns
        // its independent original pidfd1. The successful initial Agent owns
        // the connected socket and original connection-peer pidfd2. All of
        // these are actual owning fields; completed launch scratch is separate.
        let runtime_files = 1_usize + (1 + 1 + 1 + 4) + 1;
        let agent_files = agent.initial_launch_native_files_v4()?;
        let guest_files = crate::live_agent::launch_original::HostAgentLaunchOriginalV2
            ::guest_startup_retained_files_v1().ok_or(HostError::ResourceExhausted)?;
        Ok(Self {
            request: stage.request,
            files: runtime_files.checked_add(agent_files)
                .and_then(|files| files.checked_add(guest_files))
                .ok_or(HostError::ResourceExhausted)?,
        })
    }

    pub(in crate::broker::launch_handoff) fn after_disposal(
        self,
        stage: &HostLaunchOriginalV2,
    ) -> HostLaunchResidentNativeV4 {
        // The existing exclusive completion token allowed only these actual
        // infallible owning moves after preparation. A broken internal order
        // cannot fabricate a smaller current liability or release the flight.
        if stage.request != self.request || stage.first.is_some()
            || stage.opening.is_some() || stage.owner.is_some() || stage.setup.is_some()
            || stage.clock.is_some() || stage.writes.is_some() || stage.catalog.is_some()
            || stage.compilation.is_some() || stage.guardian.is_some() || stage.worker.is_some()
            || !stage.acquisition_disposed.as_ref().is_some_and(|proof|
                proof.belongs_to_request_v4(self.request))
        {
            std::process::abort();
        }
        HostLaunchResidentNativeV4 { request: self.request, files: self.files }
    }
}
