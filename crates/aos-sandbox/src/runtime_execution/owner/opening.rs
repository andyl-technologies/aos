//! Parks the four fixed Host native prefixes across their distinct admissions.
//!
//! Each recipe delegates to the existing captured writer/lock/replay/tail engine.
//! A genuine Host receiving original must pay fixed preparation before each
//! native entry and the same held extent before replay. This inert destination
//! supplies neither that original nor an execution or peer authorization.

use std::error::Error;

use aos_sandbox_core::ResourceVector;

use crate::journal::{
    CapturedJournalOpenModeV1, HostPeerCapturedJournalOpenV2,
    HostExecutionCapturedJournalOpenV2, HostAgentCapturedJournalOpenV2,
    HostLifecycleCapturedJournalOpenV2, Journal, JournalError, JournalLimits,
    ProtectedJournalPreopenReplayExtentV1, RecoveryReport,
};

use super::DormantRuntimeExecutionOwnerV1;

/// Retains all four actual fixed Host openings and every earlier positive tuple.
///
/// Unlike a consuming opener, a later failure cannot dispose an earlier native
/// prefix. The caller retains this destination through its independent posts.
#[must_use = "retain all reached native prefixes through independent posts"]
pub struct DormantRuntimeExecutionOpeningV2 {
    peer: HostPeerCapturedJournalOpenV2,
    execution: HostExecutionCapturedJournalOpenV2,
    agent: HostAgentCapturedJournalOpenV2,
    lifecycle: HostLifecycleCapturedJournalOpenV2,
    opened: [Option<(Journal, RecoveryReport)>; 4],
    prepared: [bool; 4],
    replayed: [bool; 4],
    closed: Option<JournalError>,
    taken: bool,
}

impl DormantRuntimeExecutionOpeningV2 {
    /// Constructs inert fixed destinations without opening any native object.
    #[must_use]
    pub fn new() -> Self {
        Self {
            peer: HostPeerCapturedJournalOpenV2::new(),
            execution: HostExecutionCapturedJournalOpenV2::new(),
            agent: HostAgentCapturedJournalOpenV2::new(),
            lifecycle: HostLifecycleCapturedJournalOpenV2::new(),
            opened: std::array::from_fn(|_| None),
            prepared: [false; 4],
            replayed: [false; 4],
            closed: None,
            taken: false,
        }
    }

    /// Reports the same four fixed native recipes' passive preparation demand.
    ///
    /// This excludes variable replay and Host semantic/claim work and creates
    /// no payment. Construction destination/temporary bytes are included here.
    #[must_use]
    pub fn fixed_preparation_demand_v2() -> Option<ResourceVector> {
        use aos_sandbox_core::ResourceDimension as D;

        let mut complete = ResourceVector::ZERO;
        let mut resident = 0_u64;
        let mut files = 0_u64;
        for demand in [
            HostPeerCapturedJournalOpenV2::fixed_preparation_demand().ok()?,
            HostExecutionCapturedJournalOpenV2::fixed_preparation_demand().ok()?,
            HostAgentCapturedJournalOpenV2::fixed_preparation_demand().ok()?,
            HostLifecycleCapturedJournalOpenV2::fixed_preparation_demand().ok()?,
        ] {
            files = files.max(resident.checked_add(demand.get(D::OpenFiles))?);
            // A later recipe can enter only after the preceding actual
            // take_opened transfer closed all positive native probe files.
            resident = resident.checked_add(3)?;
            complete = complete.checked_add(demand).ok()?;
        }
        complete = complete.with(D::OpenFiles, files);
        complete.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(std::mem::size_of::<Self>().checked_mul(2)?).ok()?,
        )).ok()
    }

    /// Counts the four actual retained Directory/Lock/Journal triples.
    ///
    /// This is passive custody geometry after the existing positive transfers.
    #[must_use]
    pub const fn positive_resident_files_v6() -> u64 { 4 * 3 }

    /// Checks the same completed four native transfers without reopening them.
    ///
    /// # Errors
    /// Refuses partial, failed, untransferred or still-extractable native custody.
    pub fn require_positive_residency_v6(&self) -> Result<(), JournalError> {
        if self.taken && self.opened.iter().all(Option::is_none)
            && self.peer.was_taken_positive_v1() && self.execution.was_taken_positive_v1()
            && self.agent.was_taken_positive_v1() && self.lifecycle.was_taken_positive_v1()
            && self.failure().is_none() {
            Ok(())
        } else { Err(JournalError::ProtectedBoundary) }
    }

    /// Prepares the next fixed recipe only after its caller's genuine payment.
    ///
    /// # Errors
    /// Refuses reordered/repeated entry; the native facade retains its cause.
    pub fn prepare_next_once_v2(&mut self) -> Result<usize, JournalError> {
        if self.closed.is_some() || self.taken {
            return Err(JournalError::ProtectedBoundary);
        }
        let Some(index) = self.prepared.iter().position(|prepared| !prepared) else {
            self.closed = Some(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        };
        let prior_positive = match index {
            0 => true,
            1 => self.peer.was_taken_positive_v1(),
            2 => self.execution.was_taken_positive_v1(),
            3 => self.agent.was_taken_positive_v1(),
            _ => false,
        };
        if !prior_positive || index != 0 && self.opened[index - 1].is_none() {
            self.closed = Some(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.prepared[index] = true;
        let limits = JournalLimits::default();
        let mode = CapturedJournalOpenModeV1::CreateAndRepair;
        match index {
            0 => self.peer.prepare_once(limits, mode),
            1 => self.execution.prepare_once(limits, mode),
            2 => self.agent.prepare_once(limits, mode),
            3 => self.lifecycle.prepare_once(limits, mode),
            _ => return Err(JournalError::ProtectedBoundary),
        }
        if self.captured_extent_v2(index).is_none() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(index)
    }

    /// Borrows only the same prepared prefix that must be priced before replay.
    #[must_use]
    pub fn captured_extent_v2(&self, index: usize) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        if self.closed.is_some() || self.taken || !self.prepared.get(index).copied()?
            || self.replayed.get(index).copied()?
        {
            return None;
        }
        match index {
            0 => self.peer.captured_extent(),
            1 => self.execution.captured_extent(),
            2 => self.agent.captured_extent(),
            3 => self.lifecycle.captured_extent(),
            _ => None,
        }
    }

    /// Replays only that prepared prefix after its caller's variable admission.
    ///
    /// # Errors
    /// Refuses incomplete/repeated entry or a native/parser/name failure. Every
    /// reached tuple is parked here before another fixed recipe can be entered.
    pub fn replay_prepared_once_v2(&mut self, index: usize) -> Result<(), JournalError> {
        if self.captured_extent_v2(index).is_none() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.replayed[index] = true;
        self.opened[index] = match index {
            0 => { self.peer.replay_once(); self.peer.take_opened() }
            1 => { self.execution.replay_once(); self.execution.take_opened() }
            2 => { self.agent.replay_once(); self.agent.take_opened() }
            3 => { self.lifecycle.replay_once(); self.lifecycle.take_opened() }
            _ => None,
        };
        if self.opened[index].is_none() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Moves the same four positive Journals after every final name post.
    ///
    /// This constructs a native owner, not an authenticated runtime claim.
    ///
    /// # Errors
    /// Refuses incomplete, failed or already transferred custody.
    pub fn take_owner_once_v2(&mut self) -> Result<DormantRuntimeExecutionOwnerV1, JournalError> {
        if self.taken || self.failure().is_some() || self.opened.iter().any(Option::is_none) {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.taken = true;
        // All four slots were checked under this exclusive borrow. Moving the
        // positive native tuples performs no IO or other fallible operation.
        let [Some((peer_journal, _)), Some((execution_journal, _)),
            Some((agent_journal, _)), Some((lifecycle_journal, _))] =
            self.opened.each_mut().map(Option::take)
        else {
            std::process::abort();
        };
        Ok(DormantRuntimeExecutionOwnerV1 {
            peer_journal, execution_journal, agent_journal, lifecycle_journal,
        })
    }

    /// Borrows the actual first reached native cause without another observation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.peer.failure()
            .or_else(|| self.execution.failure())
            .or_else(|| self.agent.failure())
            .or_else(|| self.lifecycle.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as &(dyn Error + 'static)))
    }
}

impl Default for DormantRuntimeExecutionOpeningV2 {
    fn default() -> Self {
        Self::new()
    }
}
