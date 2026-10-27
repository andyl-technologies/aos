//! Retains selected peer/subject proc prefixes through their exact failure.
//!
//! The same ProcessEvidence sandwich and closed final comparisons decide the
//! result. Existing bounded pidfd proc observations own the actual stat file,
//! partial bytes and parser/native error before projection. A failed error owns
//! its own raw box; no archive index, copied pin or new process proof is issued.

use super::*;
use aos_sandbox_linux::pidfd::PidFdProcObservationsV1;

pub(super) struct ProcessNativeObservationV1 {
    before: Option<Result<PidFdInfo, aos_linux_descriptors::Error>>,
    proc: Option<PidFdProcObservationsV1>,
    identity: Option<Result<PidFdProcessIdentity, aos_linux_descriptors::Error>>,
    after: Option<Result<PidFdInfo, aos_linux_descriptors::Error>>,
    alive: Option<Result<bool, aos_linux_descriptors::Error>>,
}

impl ProcessNativeObservationV1 {
    const fn new() -> Self {
        Self {
            before: None,
            proc: None,
            identity: None,
            after: None,
            alive: None,
        }
    }

    pub(super) fn before(&mut self, pidfd: &PidFd) -> Result<PidFdInfo, HandshakeError> {
        self.before = Some(pidfd.info());
        self.before.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(HandshakeError::KernelEvidence)
    }

    pub(super) fn identity(&mut self, pidfd: &PidFd) -> Result<PidFdProcessIdentity, HandshakeError> {
        self.proc = Some(aos_sandbox_linux::pidfd::prepare_proc_observations_v1(&(pidfd)));
        let Some(proc) = self.proc.as_mut() else { std::process::abort() };
        self.identity = Some(proc.capture_stat(pidfd));
        self.identity.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(HandshakeError::KernelEvidence)
    }

    pub(super) fn after(&mut self, pidfd: &PidFd) -> Result<PidFdInfo, HandshakeError> {
        self.after = Some(pidfd.info());
        self.after.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(HandshakeError::KernelEvidence)
    }

    pub(super) fn alive(&mut self, pidfd: &PidFd) -> Result<bool, HandshakeError> {
        self.alive = Some(pidfd.is_alive());
        self.alive.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(HandshakeError::KernelEvidence)
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.identity.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.alive.as_ref().and_then(|result| result.as_ref().err()))
            .map(|cause| cause as &dyn std::error::Error)
    }
}

pub(super) struct RetainedProcessEvidenceFailureV1 {
    originals: Box<ProcessNativeObservationV1>,
}

impl core::fmt::Debug for RetainedProcessEvidenceFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RetainedProcessEvidenceFailureV1")
    }
}

impl core::fmt::Display for RetainedProcessEvidenceFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("original handshake kernel evidence changed")
    }
}

impl std::error::Error for RetainedProcessEvidenceFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.originals.failure().or(Some(&HandshakeError::KernelEvidence))
    }
}

impl ProcessEvidence {
    pub(super) fn observe_retaining(
        pidfd: &PidFd,
        initial: Option<ProcessInformation>,
        final_comparison: impl FnOnce(Self) -> bool,
    ) -> Result<Self, HandshakeError> {
        let mut originals = Box::new(ProcessNativeObservationV1::new());
        let observed = Self::observe_with_originals(pidfd, initial, Some(originals.as_mut()));
        match observed {
            Ok(evidence) if final_comparison(evidence) => {
                // This whole sandwich, expected-evidence and credential check
                // completed. Dispose actual local proc/native scratch now;
                // retained original pidfd/record/custody remain with the caller.
                drop(originals);
                Ok(evidence)
            }
            _ => Err(HandshakeError::RetainedProcess(RetainedProcessEvidenceFailureV1 { originals })),
        }
    }

    pub(super) fn capture_peer_retaining(peer: &ConnectionPeerIdentity) -> Result<Self, HandshakeError> {
        Self::observe_retaining(peer.pidfd(), Some(peer.initial_info().into()), |evidence| {
            peer.credentials().pid().get() == evidence.process_id
                && peer.credentials().uid() == evidence.effective_user_id
                && peer.credentials().gid() == evidence.effective_group_id
        })
    }

    pub(super) fn validate_connection_retaining(self, peer: &ConnectionPeerIdentity) -> Result<(), HandshakeError> {
        Self::observe_retaining(peer.pidfd(), None, |current| {
            current == self && peer.credentials().pid().get() == self.process_id
                && peer.credentials().uid() == self.effective_user_id
                && peer.credentials().gid() == self.effective_group_id
        }).map(|_| ())
    }
}

/// Bounds concrete selected errors before native acquisition, without payment.
///
/// A shared reducer retains at most a primary plus two independent peer/subject
/// post errors. Four full boxes allow those three plus one active observation;
/// a fifth inline-size term conservatively pays its Box construction temporary.
/// Every raw stat buffer/parser bound comes from the actual existing reader.
pub(crate) fn receiving_failure_footprint_v1()
    -> Option<aos_sandbox_controller_domain::CreateStorageEndpointRevalidationShapeDataV1>
{
    let (heap, cells) = PidFdProcObservationsV1::stat_receiving_footprint_v1();
    Some(aos_sandbox_controller_domain::CreateStorageEndpointRevalidationShapeDataV1 {
        inline_bytes: std::mem::size_of::<ProcessNativeObservationV1>(),
        heap_bytes: 4_usize.checked_mul(std::mem::size_of::<ProcessNativeObservationV1>()
            .checked_add(heap)?.checked_add(4 * 256)?)?,
        file_descriptors: 4_usize.checked_mul(PidFdProcObservationsV1::stat_opened_file_bound_v1())?,
        // Four retained Native Results and one actual Box are outside the
        // existing proc reader's own metadata recipe. Native info/liveness
        // errors have fixed decoder/operation text; their separate4*256B
        // carrier allowance above does not borrow the proc parser's margin.
        metadata_cells: 4_usize.checked_mul(cells.checked_add(5)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_expected_evidence_keeps_real_proc_prefix_through_later_post() {
        let (socket, _remote) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let actual = ProcessEvidence::capture_peer_retaining(socket.peer()).unwrap();
        let mut stale = actual;
        stale.start_time_ticks = stale.start_time_ticks.checked_add(1).unwrap();

        // Pure stale comparison DATA, not fabricated paid receiving authority.
        // Both observations inspect the same real socket's genuine peer pin.
        let first = stale.validate_connection_retaining(socket.peer()).unwrap_err();
        let later = stale.validate_connection_retaining(socket.peer()).unwrap_err();
        let HandshakeError::RetainedProcess(first) = first else { panic!("missing original") };
        let HandshakeError::RetainedProcess(later) = later else { panic!("missing owed original") };

        assert!(matches!(first.originals.before, Some(Ok(_))));
        assert!(matches!(first.originals.identity, Some(Ok(_))));
        assert!(first.originals.proc.is_some());
        assert!(matches!(first.originals.after, Some(Ok(_))));
        assert!(matches!(first.originals.alive, Some(Ok(true))));
        assert!(later.originals.proc.is_some());
        assert!(!std::ptr::eq(first.originals.as_ref(), later.originals.as_ref()));
        assert_eq!(first.to_string(), "original handshake kernel evidence changed");
    }
}
