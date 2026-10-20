//! Retains native creation and Guest IO from the same reserved effect engine.
//!
//! The enclosing actual Host20 owner prepays this passive destination. It
//! cannot manufacture a grant, runtime claim, admitted effect or live channel.

use std::error::Error;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::immutable_file::SealedReadOnlyCredentialCreateOriginalsV1;
use aos_sandbox_linux::seqpacket::{ReceivedRecord, RetainedSeqpacketReceiveErrorV1};
use super::HostAgentLiveErrorV1;

mod ssh;
pub(crate) use ssh::GuestSshSourceQuoteDataV1;

/// Keeps reached original memfds and raw Guest records through Host posts.
#[doc(hidden)]
pub struct AgentExecutionOriginalV2 {
    pub(crate) ssh_quote: Option<GuestSshSourceQuoteDataV1>,
    pub(super) credential: SealedReadOnlyCredentialCreateOriginalsV1,
    response_mode: Option<Result<(), HostAgentLiveErrorV1>>,
    pub(super) frame: Option<Vec<u8>>,
    pub(super) send_attempts: [Option<super::send_original::AgentSendAttemptV4>;
        super::MAXIMUM_EFFECT_WRITE_ATTEMPTS_V4],
    pub(super) sent: Option<Result<(), HostAgentLiveErrorV1>>,
    pub(super) received: Option<Result<Option<Vec<u8>>, HostAgentLiveErrorV1>>,
    pub(super) record: Option<ReceivedRecord>,
    pub(super) receive_failure: Option<RetainedSeqpacketReceiveErrorV1>,
    pub(super) entered: bool,
}

impl AgentExecutionOriginalV2 {
    /// Constructs inert native destinations without performing IO.
    #[must_use]
    pub fn new() -> Self {
        Self { ssh_quote: None, credential: SealedReadOnlyCredentialCreateOriginalsV1::new(), response_mode: None,
            frame: None, send_attempts: std::array::from_fn(|_| None), sent: None, received: None, record: None, receive_failure: None, entered: false }
    }

    /// Prices the actual creator and native descriptor-free response receiver.
    ///
    /// Returns `None` on arithmetic overflow. Native socket/Agent lifetime and
    /// the upper immutable spec/grant models remain separately paid.
    #[must_use]
    pub fn receiving_demand_v2() -> Option<ResourceVector> {
        Self::receiving_profile_v5(false)
    }

    /// Prices the closed standard Observe profile before monitor IO.
    ///
    /// This destination cannot create a credential or enlarge its actual
    /// 227-byte reply ceiling. The enclosing owner pays semantic effects and
    /// retained specification models separately.
    pub(crate) fn monitor_receiving_demand_v5() -> Option<ResourceVector> {
        Self::receiving_profile_v5(true)
    }

    fn receiving_profile_v5(monitor: bool) -> Option<ResourceVector> {
        let maximum = if monitor {
            aos_sandbox_guest_protocol::signed_outcome_packet::observe_signed_outcome_packet_bytes_v5()?
        } else {
            aos_sandbox_guest_protocol::signed_outcome_packet::MAX_SIGNED_AGENT_OUTCOME_PACKET_BYTES
        };
        let request = if monitor {
            aos_sandbox_guest_protocol::protocol::observe_request_frame_bytes_v5()
        } else { aos_sandbox_guest_protocol::protocol::MAX_AGENT_FRAME_BYTES };
        let (receive, files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::closed_zero_rights_receive_obligations_v1(maximum)?;
        let (creation_bytes, creation_files, creation_names) = if monitor {
            (0, 0, 0)
        } else {
            let creation = SealedReadOnlyCredentialCreateOriginalsV1::receiving_footprint_v1(
                "aos-agent-execution-spec-v1".len(), aos_sandbox_guest_protocol::MAX_AGENT_SEALED_SPEC_BYTES_V1,
            )?;
            (creation.memory_bytes, creation.open_files, creation.metadata_entries)
        };
        // The actual selected Launch disables rights on the parent before
        // peer exposure. Both consumers require that same un-restored native
        // mode; the full authenticated80 buffers/parser remain provisioned.
        let memory = receive.checked_add(maximum.checked_mul(4)?)?
            .checked_add(creation_bytes)?.checked_add(request)?
            .checked_add(aos_sandbox_linux::seqpacket::SeqpacketSocket::agent_effect_send_receiving_bytes_v4()?)?
            .checked_add(2 * std::mem::size_of::<Self>())?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(files.checked_add(creation_files)?).ok()?)
            .with(D::MetadataEntries, u64::try_from(creation_names).ok()?)
            .with(D::NetworkBytes, u64::try_from(request.checked_add(maximum)?).ok()?))
    }

    pub(super) fn require_response_mode_v6(&mut self,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket) -> Result<(), HostAgentLiveErrorV1> {
        if self.response_mode.is_some() { return Err(HostAgentLiveErrorV1::RecoveryRequired); }
        self.response_mode = Some(require_response_mode_v6(socket));
        match self.response_mode.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(HostAgentLiveErrorV1::RecoveryRequired),
        }
    }

    /// Prices the actual Guest child/tree until native quiescence and reap.
    ///
    /// This resident term remains outside the Authorize/Observe Host-scratch
    /// peak. It changes no account, admission, execution grant or deadline.
    #[doc(hidden)]
    #[must_use]
    pub fn guest_lifetime_residency_demand_v1() -> Option<ResourceVector> {
        use aos_sandbox_linux::{cgroup, pidfd};
        let (lifetime, lifetime_files, _) = aos_sandbox_linux::process::ExecutionChildLifetimeOriginalV1::receiving_obligations_v1()?;
        let (active, active_files, _) = cgroup::CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let (child, child_files, _) = cgroup::CgroupChildOriginalV2::receiving_obligations_v2(32)?;
        let (population, population_files, _) = cgroup::CgroupPopulationMonitorOriginalV3::receiving_obligations_v3()?;
        let (identity, identity_files) = pidfd::PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let membership = cgroup::ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        let (terminal, terminal_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::
            registered_guest_monitor_receive_obligations_v2(
                aos_sandbox_guest_protocol::openssh_control::OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5,
            )?;
        let (registration, registration_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::
            guest_monitor_registration_obligations_v2(
                aos_sandbox_guest_protocol::openssh_monitor::OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2,
            )?;
        let (restriction, restriction_files) = aos_sandbox_linux::seqpacket::SeqpacketRightsRestrictionOriginalV6::
            receiving_obligations_v6()?;
        let (relay_intake, _) = aos_sandbox_linux::seqpacket::SeqpacketSocket::
            guest_monitor_receive_obligations_v1(8)?;
        let (active_control, active_control_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::
            agent_active_control_receive_obligations_v2(aos_sandbox_guest_protocol::protocol::MAX_AGENT_FRAME_BYTES)?;
        let (ssh_reader, ssh_reader_files) = aos_sandbox_linux::protected_file::FixedProtectedReadOriginalV3::
            receiving_obligations_v3(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_LOGIN_FILE_BYTES_V1)?;
        // The second descriptor registration overlaps first-registration root
        // subject+child, root socket+peer and an incoming IO socket+peer. Only
        // the completed registration ACK retires its native packet reservoir.
        let monitor_files = registration_files.checked_add(2 + 2 + 2)?
            .max(terminal_files.checked_add(8)?)
            .checked_add(2)?.checked_add(restriction_files)?;
        let bytes = lifetime.checked_add(active)?.checked_add(child)?.checked_add(population)?
            .checked_add(identity.checked_mul(3)?)?.checked_add(membership.checked_mul(2)?)?
            .checked_add(2 * std::mem::size_of::<pidfd::PidFdOpenAttemptV1>())?
            .checked_add(aos_sandbox_guest_protocol::capture_receiving::CAPTURE_GUEST_CONTROL_BYTES_V2)?
            .checked_add(terminal)?.checked_add(registration)?.checked_add(restriction)?
            .checked_add(relay_intake)?.checked_add(1)?
            .checked_add(active_control)?.checked_add(restriction)?.checked_add(1)?
            .checked_add(ssh_reader)?.checked_add(identity)?
            .checked_add(aos_sandbox_guest_protocol::openssh_receiving::openssh_install_input_bytes_v1()?)?;
        let files = lifetime_files.checked_add(active_files)?.checked_add(child_files)?
            .checked_add(population_files)?.checked_add(identity_files.checked_mul(3)?)?
            .checked_add(cgroup::ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)?)?
            // Four exact control files, migration file, opened leader pidfd,
            // std Child's possible pidfd, five pipe/PTy/null endpoints and
            // record+directory write files all have owning destinations.
            .checked_add(4 + 1 + 1 + 1 + 5 + 2)?
            // Source-counted registration versus registered zero-rights phase,
            // plus actual same daemon Child/listener ownership, above.
            .checked_add(monitor_files)?
            // The Agent control receive can fail while all Guest native owners
            // remain live. Its distinct proof and raw native3 remain co-live.
            .checked_add(active_control_files)?.checked_add(restriction_files)?
            // Full-positive reader/writer phases physically close their files
            // before daemon spawn or identity. The existing daemon2 term above
            // remains paid throughout; this adds the largest other native plane.
            .checked_add(ssh_reader_files.max(2).max(identity_files).max(
                aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_DAEMON_SPAWN_FILES_V1.checked_sub(2)?))?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            // Execution directory, its five named controls, proc stat, the
            // original row+temporary replacement, exact helper image and two
            // actual live/IO registry keys. Rust carrier fields are not rows.
            // Three protected directories and each writer's literal final and
            // temporary name are actual namespace entries, not Rust fields.
            .with(D::MetadataEntries, 12 + 7)
            .with(D::StorageBytes, u64::try_from(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_INSTALL_RECORD_BYTES_V1.checked_mul(2)?).ok()?)
            .with(D::PublicationStagingBytes, u64::try_from(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_INSTALL_RECORD_BYTES_V1.checked_mul(2)?).ok()?)
            .with(D::Pids, 2)
            .with(D::OutputBytes, u64::try_from(aos_sandbox_guest_protocol::MAX_AGENT_SEALED_SPEC_BYTES_V1
                .checked_add(36)?.checked_add(aos_sandbox_guest_protocol::capture_receiving::CAPTURE_GUEST_CONTROL_BYTES_V2)?).ok()?)
            .with(D::NetworkBytes, u64::try_from(aos_sandbox_guest_protocol::MAX_AGENT_SEALED_SPEC_BYTES_V1.checked_add(36)?).ok()?))
    }

    pub(crate) const fn has_entered_v2(&self) -> bool {
        self.entered
    }

    pub(crate) fn completed_positive_v2(&self) -> bool {
        self.entered && self.failure().is_none()
            && self.send_attempts.iter().flatten().all(|attempt|
                attempt.guard.is_none() && (attempt.native.is_sent() || attempt.native.is_nonconsuming()))
            && matches!(self.sent, Some(Ok(())))
            && matches!(self.received, Some(Ok(_))) && self.record.is_some()
    }

    /// Borrows the actual first failed native frontier without recapture.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.response_mode.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.credential.failure())
            .or_else(|| self.send_attempts.iter().flatten()
                .filter(|attempt| !attempt.native.is_nonconsuming()
                    || !matches!(self.sent, Some(Ok(()))))
                .find_map(super::send_original::AgentSendAttemptV4::failure))
            .or_else(|| self.sent.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.receive_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.received.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl Default for AgentExecutionOriginalV2 {
    fn default() -> Self { Self::new() }
}

// The borrower observes only the actual private socket's native construction
// disposition. It grants no Agent/currentness/effect permission. The shared
// receiver independently checks the kernel option on every selected sample.
pub(super) fn require_response_mode_v6(socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket)
    -> Result<(), HostAgentLiveErrorV1> {
    if socket.zero_rights_receive_obligations_v1(1).is_none() {
        return Err(HostAgentLiveErrorV1::RecoveryRequired);
    }
    Ok(())
}

#[cfg(test)]
mod native_mode_tests {
    use super::*;
    use aos_sandbox_linux::seqpacket::{RecordSubjectSeqpacketPairOriginalV2, SeqpacketSocket};

    #[test]
    fn selected_original_requires_actual_unrestored_parent_mode_before_io() {
        let mut pair = RecordSubjectSeqpacketPairOriginalV2::zero_rights_parent_v1();
        pair.prepare().unwrap();
        let mut parent = pair.take_parent_socket().unwrap();
        let child = SeqpacketSocket::from_owned(pair.take_child_endpoint().unwrap()).unwrap();
        let mut selected = AgentExecutionOriginalV2::new();
        let mut ordinary = AgentExecutionOriginalV2::new();

        assert!(selected.require_response_mode_v6(&parent).is_ok());
        assert!(ordinary.require_response_mode_v6(&child).is_err());
        assert!(ordinary.failure().is_some());
        assert!(child.as_fd().is_ok());
        assert!(selected.require_response_mode_v6(&parent).is_err());
        parent.restore_rights_once_v1().unwrap();
        assert!(require_response_mode_v6(&parent).is_err());
        assert!(parent.as_fd().is_ok());
    }
}
