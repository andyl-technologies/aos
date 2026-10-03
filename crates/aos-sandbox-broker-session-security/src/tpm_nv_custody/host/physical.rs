//! Retains genuine Host journals and one failed-or-live physical read attempt.
//!
//! Construction parks the actual whole journal owner. Fallible admission uses
//! a mutable borrow of this retained consumer, not a temporary that disappears
//! on error or caught unwind. The common physical owner alone runs the carrier.
//! Fresh classification is DATA under that owner, never a recovery/effect permit.

use std::error::Error;
use std::fmt;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox::{HostPhysicalInvocationErrorV1, HostPhysicalInvocationLeaseV1};
use aos_sandbox_linux::guest_confinement::task_has_subject;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::{ReceivedRecord, RetainedSeqpacketReceiveErrorV1, SeqpacketError};
use zeroize::Zeroizing;

use super::journal::{HeldHostPhysicalJournalV1, HostOwnedJournalInputsV1};
use super::store::StoredHostFloorV1;
use super::{HostOwnedJournalErrorV1, HostTpmAdmissionErrorV1};
use crate::tpm_nv_custody::framing::{AUTH_BYTES, HELLO_BYTES, REQUEST_BYTES, HelperObservationV1};
use crate::tpm_nv_custody::physical::RetainedPhysicalTpmOwnerV1;
use crate::tpm_nv_custody::{
    FloorErrorV1, FloorRecoveryV1, NvCustodyErrorV1, NV_ATTRIBUTES_WRITTEN,
    reconcile_host_floor_data_v1,
};

const HELPER_SUBJECT: &str = "system_u:system_r:aos_runtime_deployment_helper_t";

/// Shares only a retained diagnostic, never a physical owner or retry right.
#[derive(Clone, Debug)]
pub(in crate::tpm_nv_custody) struct HostPhysicalReadErrorV1 {
    cause: Arc<PhysicalTpmFailureV1>,
}

impl HostPhysicalReadErrorV1 {
    pub(in crate::tpm_nv_custody) fn wrong_owner() -> Self {
        Self {
            cause: Arc::new(PhysicalTpmFailureV1::State),
        }
    }
}

impl fmt::Display for HostPhysicalReadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Host physical read attempt is permanently unavailable")
    }
}

impl Error for HostPhysicalReadErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

/// Keeps provider errors typed; the Broker facade projects only its old cases.
#[derive(Debug, thiserror::Error)]
pub(in crate::tpm_nv_custody) enum PhysicalTpmFailureV1 {
    #[error("original floor observation failed")]
    Floor(#[from] FloorErrorV1),
    #[error("original Host journal failed")]
    Journal(#[from] HostOwnedJournalErrorV1),
    #[error("original Host inputs failed")]
    Inputs(#[from] HostTpmAdmissionErrorV1),
    #[error("original Host invocation failed")]
    Invocation(#[from] HostPhysicalInvocationErrorV1),
    #[error("original process observation failed")]
    Linux(#[source] aos_sandbox_linux::Error),
    #[error("original private carrier failed")]
    Carrier(#[source] NvCustodyErrorV1),
    #[error("original private send failed")]
    Send(#[source] SeqpacketError),
    #[error("original strict receive failed with retained custody")]
    Receive(#[source] RetainedSeqpacketReceiveErrorV1),
    #[error("original helper spawn or child observation failed")]
    Child(#[source] std::io::Error),
    #[error("original kernel nonce acquisition failed")]
    Entropy(#[source] crate::BrokerSessionSecurityError),
    #[error("Host physical attempt is not in its required one-shot state")]
    State,
    #[error("Host physical attempt did not complete")]
    Unfinished,
    #[error("original Host disk association changed around fresh NV")]
    Changed,
}

impl PhysicalTpmFailureV1 {
    pub(in crate::tpm_nv_custody) fn broker_error(self) -> FloorErrorV1 {
        match self {
            Self::Floor(error) => error,
            // No Host/retaining branch is used by the restricted Broker arm.
            _ => FloorErrorV1::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::tpm_nv_custody) enum HostAttemptPhaseV1 {
    Fresh,
    Checking,
    Ready,
    Failed,
}

// This phase lives on the actual retained binding. Only successful measurement
// of its original child before HELLO advances it; DATA cannot set owner state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostHelperImagePhaseV1 {
    AwaitingPreHelloMeasurement,
    MeasuredBeforeHello,
}

impl HostHelperImagePhaseV1 {
    fn require_pre_hello_measurement(self) -> Result<(), PhysicalTpmFailureV1> {
        if self != Self::AwaitingPreHelloMeasurement {
            return Err(PhysicalTpmFailureV1::State);
        }
        Ok(())
    }

    fn require_measured(self) -> Result<(), PhysicalTpmFailureV1> {
        if self != Self::MeasuredBeforeHello {
            return Err(PhysicalTpmFailureV1::State);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(in crate::tpm_nv_custody) enum HostFrameV1 {
    Hello,
    Auth,
    Request,
}

#[derive(Clone, Copy)]
pub(in crate::tpm_nv_custody) enum HostReplyV1 {
    Acknowledgment,
    Observation,
}

/// Holds bounded exact sent bytes and actual record/process custody.
///
/// Secret AUTH remains zeroizing and has no diagnostic/body accessor. There
/// are three fixed sent slots and two received slots, never an unbounded log.
struct HostCarrierDebtV1 {
    hello: Option<Zeroizing<[u8; HELLO_BYTES]>>,
    auth: Option<Zeroizing<[u8; AUTH_BYTES]>>,
    request: Option<[u8; REQUEST_BYTES]>,
    hello_attempted: bool,
    auth_attempted: bool,
    request_attempted: bool,
    main_lock: Option<aos_sandbox::ProtectedJournalLockCustodyV1>,
    sidecar_lock: Option<aos_sandbox::ProtectedJournalLockCustodyV1>,
    acknowledgment: Option<ReceivedRecord>,
    observation: Option<ReceivedRecord>,
}

/// Has no independent constructor from inputs, Names, leases or descriptor DATA.
pub(in crate::tpm_nv_custody) struct RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup> {
    journal: HeldHostPhysicalJournalV1<'owner, 'origin, 'startup>,
    invocation: Option<HostPhysicalInvocationLeaseV1<'origin, 'startup>>,
    phase: HostAttemptPhaseV1,
    helper_image_phase: HostHelperImagePhaseV1,
    first_failure: Option<Arc<PhysicalTpmFailureV1>>,
    compared_before: Option<(StoredHostFloorV1, [u8; 32])>,
    debt: HostCarrierDebtV1,
}

impl<'owner, 'origin, 'startup> RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup> {
    fn park(owner: &'owner mut HostOwnedJournalInputsV1<'origin, 'startup>) -> Self {
        Self {
            journal: HeldHostPhysicalJournalV1::park(owner),
            invocation: None,
            phase: HostAttemptPhaseV1::Fresh,
            helper_image_phase: HostHelperImagePhaseV1::AwaitingPreHelloMeasurement,
            first_failure: None,
            compared_before: None,
            debt: HostCarrierDebtV1 {
                hello: None,
                auth: None,
                request: None,
                hello_attempted: false,
                auth_attempted: false,
                request_attempted: false,
                main_lock: None,
                sidecar_lock: None,
                acknowledgment: None,
                observation: None,
            },
        }
    }

    pub(in crate::tpm_nv_custody) fn begin(
        &mut self,
        expected: HostAttemptPhaseV1,
    ) -> Result<(), HostPhysicalReadErrorV1> {
        if let Err(cause) = begin_phase(&mut self.phase, expected) {
            return Err(self.fail(cause));
        }
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn complete(&mut self) -> Result<(), HostPhysicalReadErrorV1> {
        complete_phase(&mut self.phase).map_err(|cause| self.fail(cause))
    }

    pub(in crate::tpm_nv_custody) fn close(&mut self) {
        // Both originals are fenced before lease Drop or diagnostic retention.
        self.phase = HostAttemptPhaseV1::Failed;
        self.journal.close();
        drop(self.invocation.take());
    }

    pub(in crate::tpm_nv_custody) fn fail(
        &mut self,
        cause: PhysicalTpmFailureV1,
    ) -> HostPhysicalReadErrorV1 {
        self.close();
        retain_first_failure(&mut self.first_failure, cause)
    }

    pub(in crate::tpm_nv_custody) fn claim_invocation(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        // Derive ONLY from this same parked journal owner's genuine Origins.
        self.invocation = Some(self.journal.claim_invocation()?);
        self.recheck()?;
        Ok(())
    }

    fn compared_state(
        &mut self,
    ) -> Result<(StoredHostFloorV1, [u8; 32]), PhysicalTpmFailureV1> {
        if self.phase != HostAttemptPhaseV1::Checking {
            return Err(PhysicalTpmFailureV1::State);
        }
        self.invocation.as_mut().ok_or(PhysicalTpmFailureV1::State)?
            .recheck()?;
        let state = self.journal.compare_state()?;
        self.invocation.as_mut().ok_or(PhysicalTpmFailureV1::State)?
            .recheck()?;
        Ok(state)
    }

    pub(in crate::tpm_nv_custody) fn recheck(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        self.compared_state()?;
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn capture_disk_cut(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        self.compared_before = Some(self.compared_state()?);
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn require_disk_cut(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        let current = self.compared_state()?;
        if self.compared_before.as_ref() != Some(&current) {
            return Err(PhysicalTpmFailureV1::Changed);
        }
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn classify_observation(
        &mut self,
        observed: HelperObservationV1,
    ) -> Result<FloorRecoveryV1, PhysicalTpmFailureV1> {
        let current = self.compared_state()?;
        let before = self.compared_before.as_ref()
            .ok_or(PhysicalTpmFailureV1::State)?;
        if &current != before {
            return Err(PhysicalTpmFailureV1::Changed);
        }
        let (expected_name, _) = self.names();
        if observed.name != expected_name
            || observed.name_algorithm != 0x000b
            || observed.attributes != NV_ATTRIBUTES_WRITTEN
            || observed.size != 32
            || observed.policy_length != 0
            || observed.value == [0; 32]
        {
            return Err(FloorErrorV1::Provisioning.into());
        }
        let (stored, scope) = before;
        let classification = reconcile_host_floor_data_v1(
            *scope,
            stored.checkpoint,
            stored.prepared.as_ref().map(|(intent, _)| *intent),
            stored.current,
            observed.value,
        )?;
        let after = self.compared_state()?;
        if self.compared_before.as_ref() != Some(&after) {
            return Err(PhysicalTpmFailureV1::Changed);
        }
        Ok(classification)
    }

    pub(in crate::tpm_nv_custody) fn helper_path(&self) -> &Path {
        self.journal.helper_path()
    }

    pub(in crate::tpm_nv_custody) fn measure_helper_before_hello(
        &mut self,
        pidfd: &PidFd,
        pid: u32,
    ) -> Result<(), PhysicalTpmFailureV1> {
        self.helper_image_phase.require_pre_hello_measurement()?;
        if self.phase != HostAttemptPhaseV1::Checking
            || self.debt.hello.is_none()
            || self.debt.hello_attempted
        {
            return Err(PhysicalTpmFailureV1::State);
        }
        self.recheck()?;
        self.journal.require_executed_helper(pid)?;
        self.require_helper_subject_and_invocation(pidfd)?;
        self.recheck()?;
        if !pidfd.is_alive().map_err(PhysicalTpmFailureV1::Linux)? {
            return Err(FloorErrorV1::Unavailable.into());
        }

        // C becomes nondumpable before ACK and never execs/forks afterward.
        // Latch only after the complete original check; later custody retains
        // image names/content and the same child, not ptrace-gated proc images.
        self.helper_image_phase = HostHelperImagePhaseV1::MeasuredBeforeHello;
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn require_measured_helper(
        &mut self,
        pidfd: &PidFd,
    ) -> Result<(), PhysicalTpmFailureV1> {
        self.helper_image_phase.require_measured()?;
        // The original input recheck includes image.revalidate; it never
        // reopens this now-nondumpable child's executable or mappings.
        self.recheck()?;
        self.require_helper_subject_and_invocation(pidfd)?;
        self.recheck()
    }

    fn require_helper_subject_and_invocation(
        &mut self,
        pidfd: &PidFd,
    ) -> Result<(), PhysicalTpmFailureV1> {
        if !task_has_subject(pidfd, HELPER_SUBJECT).map_err(PhysicalTpmFailureV1::Linux)? {
            return Err(FloorErrorV1::Provisioning.into());
        }
        self.invocation.as_mut().ok_or(PhysicalTpmFailureV1::State)?
            .require_child(pidfd)?;
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn names(&self) -> ([u8; 34], [u8; 34]) {
        self.journal.names()
    }

    pub(in crate::tpm_nv_custody) fn retain_locks(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        self.recheck()?;
        self.debt.main_lock = Some(self.journal.loan_main()?);
        self.debt.sidecar_lock = Some(self.journal.loan_sidecar()?);
        self.recheck()?;
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn lock_fds(
        &self,
    ) -> Result<[BorrowedFd<'_>; 2], PhysicalTpmFailureV1> {
        Ok([
            self.debt.main_lock.as_ref().ok_or(PhysicalTpmFailureV1::State)?.as_fd(),
            self.debt.sidecar_lock.as_ref().ok_or(PhysicalTpmFailureV1::State)?.as_fd(),
        ])
    }

    pub(in crate::tpm_nv_custody) fn lock_identities(
        &self,
    ) -> Result<[(u64, u64, u32); 2], PhysicalTpmFailureV1> {
        Ok([
            self.debt.main_lock.as_ref().ok_or(PhysicalTpmFailureV1::State)?
                .identity().map_err(HostOwnedJournalErrorV1::Journal)?,
            self.debt.sidecar_lock.as_ref().ok_or(PhysicalTpmFailureV1::State)?
                .identity().map_err(HostOwnedJournalErrorV1::Journal)?,
        ])
    }

    pub(in crate::tpm_nv_custody) fn current_auth(
        &mut self,
    ) -> Result<Zeroizing<[u8; 32]>, PhysicalTpmFailureV1> {
        self.recheck()?;
        let auth = self.journal.current_auth()?;
        self.recheck()?;
        Ok(auth)
    }

    pub(in crate::tpm_nv_custody) fn stage_hello(&mut self, bytes: Zeroizing<[u8; HELLO_BYTES]>) {
        self.debt.hello = Some(bytes);
    }

    pub(in crate::tpm_nv_custody) fn stage_auth(&mut self, bytes: Zeroizing<[u8; AUTH_BYTES]>) {
        self.debt.auth = Some(bytes);
    }

    pub(in crate::tpm_nv_custody) fn stage_request(&mut self, bytes: [u8; REQUEST_BYTES]) {
        // Only a completed healthy read permits a new operation. The previous
        // request/record may be replaced; a failed operation can never rotate
        // these fixed debt slots or overtake the retained ambiguous attempt.
        self.debt.request = Some(bytes);
        self.debt.request_attempted = false;
    }

    pub(in crate::tpm_nv_custody) fn note_attempt(&mut self, frame: HostFrameV1) {
        match frame {
            HostFrameV1::Hello => self.debt.hello_attempted = true,
            HostFrameV1::Auth => self.debt.auth_attempted = true,
            HostFrameV1::Request => self.debt.request_attempted = true,
        }
    }

    pub(in crate::tpm_nv_custody) fn stage_reply(&mut self, kind: HostReplyV1, record: ReceivedRecord) {
        match kind {
            HostReplyV1::Acknowledgment => self.debt.acknowledgment = Some(record),
            HostReplyV1::Observation => self.debt.observation = Some(record),
        }
    }

    pub(in crate::tpm_nv_custody) fn reply(
        &self,
        kind: HostReplyV1,
    ) -> Result<&ReceivedRecord, PhysicalTpmFailureV1> {
        match kind {
            HostReplyV1::Acknowledgment => self.debt.acknowledgment.as_ref(),
            HostReplyV1::Observation => self.debt.observation.as_ref(),
        }
        .ok_or(PhysicalTpmFailureV1::State)
    }
}

fn begin_phase(
    phase: &mut HostAttemptPhaseV1,
    expected: HostAttemptPhaseV1,
) -> Result<(), PhysicalTpmFailureV1> {
    if !matches!(expected, HostAttemptPhaseV1::Fresh | HostAttemptPhaseV1::Ready)
        || *phase != expected
    {
        *phase = HostAttemptPhaseV1::Failed;
        return Err(PhysicalTpmFailureV1::State);
    }
    *phase = HostAttemptPhaseV1::Checking;
    Ok(())
}

fn complete_phase(phase: &mut HostAttemptPhaseV1) -> Result<(), PhysicalTpmFailureV1> {
    if *phase != HostAttemptPhaseV1::Checking {
        *phase = HostAttemptPhaseV1::Failed;
        return Err(PhysicalTpmFailureV1::State);
    }
    *phase = HostAttemptPhaseV1::Ready;
    Ok(())
}

// The whole owner and invocation have already been closed at this call site.
fn retain_first_failure(
    first: &mut Option<Arc<PhysicalTpmFailureV1>>,
    cause: PhysicalTpmFailureV1,
) -> HostPhysicalReadErrorV1 {
    let cause = first.get_or_insert_with(|| Arc::new(cause));
    HostPhysicalReadErrorV1 {
        cause: Arc::clone(cause),
    }
}

/// Retains partial admission/failure debt instead of returning a naked error.
///
/// Its only constructor parks the genuine whole owner; fallible operations
/// borrow this retained object so errors or caught unwind keep all actual debt.
/// Ordinary Drop performs existing child cleanup but proves no population drain.
#[must_use = "keep the same Host owner and physical failure debt retained"]
pub(super) struct HostPhysicalReadConsumerV1<'owner, 'origin, 'startup> {
    physical: RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup>,
}

impl<'owner, 'origin, 'startup> HostPhysicalReadConsumerV1<'owner, 'origin, 'startup> {
    pub(super) fn retain(owner: &'owner mut HostOwnedJournalInputsV1<'origin, 'startup>) -> Self {
        Self {
            physical: RetainedPhysicalTpmOwnerV1::retain_host(
                RetainedHostPhysicalBindingV1::park(owner),
            ),
        }
    }

    /// Admits the one original fixed055 carrier and classifies a fresh read.
    ///
    /// # Errors
    /// Permanently closes both whole owner and invocation, preserving the first
    /// typed cause and actual partial carrier/child/lock/frame debt in self.
    pub(super) fn admit(&mut self) -> Result<FloorRecoveryV1, HostPhysicalReadErrorV1> {
        self.physical.admit_host()
    }

    /// Repeats fresh authenticated read/classification under the SAME owner.
    ///
    /// # Errors
    /// Rejects prior failure or original/session/disk drift with retained debt.
    /// This cannot extend NV, write/recover journals or create a restart permit.
    pub(super) fn classify(&mut self) -> Result<FloorRecoveryV1, HostPhysicalReadErrorV1> {
        self.physical.classify_host()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These vectors exercise inert phase/diagnostic helpers only. They create
    // no Origins, journal owner, process, socket, lock, invocation or NV proof.
    #[test]
    fn ordinary_helper_custody_requires_completed_pre_hello_measurement() {
        let unmeasured = HostHelperImagePhaseV1::AwaitingPreHelloMeasurement;
        let measured = HostHelperImagePhaseV1::MeasuredBeforeHello;

        assert!(matches!(
            unmeasured.require_measured(),
            Err(PhysicalTpmFailureV1::State),
        ));
        measured.require_measured().unwrap();
    }

    #[test]
    fn executed_helper_measurement_is_only_the_initial_image_phase() {
        let unmeasured = HostHelperImagePhaseV1::AwaitingPreHelloMeasurement;
        let measured = HostHelperImagePhaseV1::MeasuredBeforeHello;

        unmeasured.require_pre_hello_measurement().unwrap();
        assert!(matches!(
            measured.require_pre_hello_measurement(),
            Err(PhysicalTpmFailureV1::State),
        ));
    }

    #[test]
    fn initial_and_repeated_read_phases_require_completed_checks() {
        let mut phase = HostAttemptPhaseV1::Fresh;

        begin_phase(&mut phase, HostAttemptPhaseV1::Fresh).unwrap();
        assert_eq!(phase, HostAttemptPhaseV1::Checking);
        complete_phase(&mut phase).unwrap();
        assert_eq!(phase, HostAttemptPhaseV1::Ready);

        begin_phase(&mut phase, HostAttemptPhaseV1::Ready).unwrap();
        complete_phase(&mut phase).unwrap();
        assert_eq!(phase, HostAttemptPhaseV1::Ready);
    }

    #[test]
    fn repeated_admission_and_read_before_admission_permanently_fail() {
        for (initial, expected) in [
            (HostAttemptPhaseV1::Ready, HostAttemptPhaseV1::Fresh),
            (HostAttemptPhaseV1::Fresh, HostAttemptPhaseV1::Ready),
        ] {
            let mut phase = initial;

            assert!(matches!(
                begin_phase(&mut phase, expected),
                Err(PhysicalTpmFailureV1::State),
            ));
            assert_eq!(phase, HostAttemptPhaseV1::Failed);
            assert!(complete_phase(&mut phase).is_err());
            assert!(begin_phase(&mut phase, HostAttemptPhaseV1::Fresh).is_err());
            assert!(begin_phase(&mut phase, HostAttemptPhaseV1::Ready).is_err());
        }
    }

    #[test]
    fn incomplete_and_failed_phases_cannot_be_reopened() {
        for initial in [HostAttemptPhaseV1::Checking, HostAttemptPhaseV1::Failed] {
            for expected in [
                HostAttemptPhaseV1::Fresh,
                HostAttemptPhaseV1::Ready,
                HostAttemptPhaseV1::Checking,
                HostAttemptPhaseV1::Failed,
            ] {
                let mut phase = initial;

                assert!(begin_phase(&mut phase, expected).is_err());
                assert_eq!(phase, HostAttemptPhaseV1::Failed);
            }
        }
    }

    #[test]
    fn completion_does_not_restore_nonchecking_phases() {
        for initial in [
            HostAttemptPhaseV1::Fresh,
            HostAttemptPhaseV1::Ready,
            HostAttemptPhaseV1::Failed,
        ] {
            let mut phase = initial;

            assert!(complete_phase(&mut phase).is_err());
            assert_eq!(phase, HostAttemptPhaseV1::Failed);
        }
    }

    #[test]
    fn repeated_failures_retain_the_exact_first_typed_cause() {
        let mut first = None;
        let initial = retain_first_failure(&mut first, PhysicalTpmFailureV1::Changed);

        let later = retain_first_failure(&mut first, PhysicalTpmFailureV1::Unfinished);
        let diagnostic = initial.clone();

        assert!(Arc::ptr_eq(&initial.cause, &later.cause));
        assert!(Arc::ptr_eq(&initial.cause, &diagnostic.cause));
        assert!(matches!(
            later.cause.as_ref(),
            PhysicalTpmFailureV1::Changed,
        ));
        assert_eq!(
            initial.to_string(),
            "Host physical read attempt is permanently unavailable",
        );
        assert!(initial.source().is_some());
    }
}
