//! Same-Session initial current-cut request custody without common readiness.
//!
//! One fixed query is sent once, survives backpressure and owns its immutable
//! response. Child and original endpoint checks bracket each receive. Failure
//! is sticky; no new operation or automatic retry can replace the request.

use crucible_node_format::U64;
use crucible_qemu_protocol::node_control::{NativeFrame, NativeStoppedCut, NativeStoppedCutQuery};

use super::{ArchiveError, NativeOwnedPrefixSession, OriginalOperationEndpoint, TurnoverState};

pub(super) struct StoppedAttempt {
    query: NativeStoppedCutQuery,
    sent: bool,
    observation: Option<NativeStoppedCut>,
    failed: bool,
}

impl StoppedAttempt {
    pub(super) fn complete(&self) -> bool {
        !self.failed && self.observation.is_some()
    }

    pub(super) fn into_observation(self) -> Option<NativeStoppedCut> {
        self.observation
    }
}

impl NativeOwnedPrefixSession {
    /// Retains the one initial current-cut query under this actual Session.
    ///
    /// This pure observation supplies no Ready or effect permission. It cannot
    /// run on an old endpoint, before consumed initial ACK or after Compute.
    ///
    /// # Errors
    /// Refuses dead/foreign ownership, unsettled initial custody or a failed query.
    pub fn begin_stopped_cut(&mut self) -> Result<(), ArchiveError> {
        self.check_child()?;
        if !self.preparation.settled()
            || self.archive.state() != TurnoverState::Vacant
            || !self.preparation.endpoint().stopped_observation_selected()
        {
            return Err(ArchiveError::Conflict);
        }
        if let Some(original) = &self.stopped {
            return if original.failed {
                Err(ArchiveError::Failed)
            } else {
                Ok(())
            };
        }
        let preparation = self
            .preparation
            .endpoint()
            .prefix_preparation()
            .ok_or(ArchiveError::Conflict)?;
        let query = NativeStoppedCutQuery {
            scope: preparation
                .original_effect
                .original_root
                .administration
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()?,
            prefix_preparation: preparation.identity_digest()?,
            sequence: U64::new(1),
        };
        query.encode()?;
        self.stopped = Some(StoppedAttempt {
            query,
            sent: false,
            observation: None,
            failed: false,
        });
        Ok(())
    }

    /// Polls the same source observation once without resending after exposure.
    ///
    /// # Errors
    /// Retains permanent failure for dead/foreign Child, changed body, framing or
    /// consumed-ACK mismatch. Missing data remains pending under this query.
    pub fn poll_stopped_cut(&mut self) -> Result<bool, ArchiveError> {
        if self.stopped.as_ref().is_some_and(|attempt| attempt.failed) {
            return Err(ArchiveError::Failed);
        }
        let result = self.poll_stopped_cut_once();
        if result.is_err()
            && let Some(attempt) = &mut self.stopped
        {
            attempt.failed = true;
        }
        result
    }

    /// Borrows ordinary data retained from this original Session observation.
    pub fn stopped_cut(&self) -> Option<&NativeStoppedCut> {
        self.stopped
            .as_ref()
            .and_then(|attempt| attempt.observation.as_ref())
    }

    fn poll_stopped_cut_once(&mut self) -> Result<bool, ArchiveError> {
        self.check_child()?;
        let endpoint = self.preparation.endpoint();
        if !endpoint.original_process_matches(self.child.process_id())
            || !self.preparation.settled()
            || self.archive.state() != TurnoverState::Vacant
        {
            return Err(ArchiveError::Conflict);
        }
        let attempt = self.stopped.as_mut().ok_or(ArchiveError::Conflict)?;
        if attempt.complete() {
            return Ok(true);
        }
        if !attempt.sent {
            if !endpoint.send_original(&NativeFrame::QueryStoppedCut(attempt.query.clone()))? {
                return Ok(false);
            }
            attempt.sent = true;
        }
        let Some(frame) = endpoint.receive_original()? else {
            self.check_child()?;
            return Ok(false);
        };
        let NativeFrame::StoppedCut(observation) = frame else {
            return Err(ArchiveError::Conflict);
        };
        let facts = self.preparation.facts().ok_or(ArchiveError::Conflict)?;
        let preparation = self.preparation.store().preparation();
        let original =
            facts.observe_original(preparation, self.preparation.store().initialization())?;
        let consumed = self
            .preparation
            .consumed_acknowledgement()
            .ok_or(ArchiveError::Conflict)?;
        observation.validate_original(
            &attempt.query,
            &original,
            consumed,
            self.child.process_id(),
        )?;
        attempt.observation = Some(*observation);
        self.check_child()?;
        Ok(true)
    }
}
