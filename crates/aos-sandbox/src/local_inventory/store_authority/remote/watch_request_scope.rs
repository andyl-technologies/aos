//! Finite native watch loans retaining actual replay and resync custody.
//!
//! Native factories retain fixed-owner/context checks and the exact old state
//! holders. Coordinator owns request assembly, cursor-floor selection and bounds.
//! No public raw enum, map or receipt can create one of these native loans.

use super::*;
use aos_sandbox_core::{
    InvalidMultiNodeProtocol, MAX_WATCH_EVENTS, NodeRequestBodyV1, NodeWatchBindingV1,
    NodeWatchCursorV1,
};

enum WatchRequestSelectionV1 {
    Bootstrap,
    Resume,
    Compaction,
    Resync,
}

/// Retains the real watch owner/session and exact existing readback or gap.
pub struct ProtectedWatchRequestScopeV1<'owner, 'session> {
    retained_gap: Option<ProtectedWatchResyncRequiredV1>,
    retained_state: Option<WatchJournalStateV1>,
    owner: &'owner mut ProtectedMultiNodeAuthorityOwnerV1,
    session: &'session AuthenticatedNodeSessionV1,
    binding: NodeWatchBindingV1,
    cursor: Option<NodeWatchCursorV1>,
    selection: WatchRequestSelectionV1,
}

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Borrows the actual fixed owner for its native bootstrap binding.
    ///
    /// # Errors
    ///
    /// Returns the original protected-context/session/schema mismatch.
    pub fn begin_watch_bootstrap_request_once_v1<'owner, 'session>(
        &'owner mut self,
        session: &'session AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedWatchRequestScopeV1<'owner, 'session>, InvalidMultiNodeProtocol> {
        let binding = self.protected_watch_binding(session)?;
        Ok(ProtectedWatchRequestScopeV1 {
            retained_gap: None,
            retained_state: None,
            owner: self,
            session,
            binding,
            cursor: None,
            selection: WatchRequestSelectionV1::Bootstrap,
        })
    }

    /// Borrows actual current watch replay for the existing resume request.
    ///
    /// # Errors
    ///
    /// Returns the original replay/HistoryGap or current session-binding refusal.
    pub fn begin_watch_resume_request_once_v1<'owner, 'session>(
        &'owner mut self,
        session: &'session AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedWatchRequestScopeV1<'owner, 'session>, ProtectedMultiNodeUpdateErrorV1>
    {
        self.begin_current_watch_request_once_v1(session, WatchRequestSelectionV1::Resume)
    }

    /// Borrows actual same-policy watch replay before selecting its next floor.
    ///
    /// # Errors
    ///
    /// Returns the original replay/HistoryGap or session-binding refusal.
    pub fn begin_watch_compaction_request_once_v1<'owner, 'session>(
        &'owner mut self,
        session: &'session AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedWatchRequestScopeV1<'owner, 'session>, ProtectedMultiNodeUpdateErrorV1>
    {
        self.begin_current_watch_request_once_v1(session, WatchRequestSelectionV1::Compaction)
    }

    // Both public entry points retain the same complete native acquisition.
    // Only their private request selector differs; no caller chooses a phase.
    fn begin_current_watch_request_once_v1<'owner, 'session>(
        &'owner mut self,
        session: &'session AuthenticatedNodeSessionV1,
        selection: WatchRequestSelectionV1,
    ) -> Result<ProtectedWatchRequestScopeV1<'owner, 'session>, ProtectedMultiNodeUpdateErrorV1>
    {
        let state = match self.current_domain_projection(MultiNodeJournalDomainV1::Watch)? {
            Some(MultiNodeReducerStateV1::Watch(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let binding = state.binding();
        if binding.coordinator_epoch() != session.coordinator_epoch()
            || binding.audience_digest() != session.audience_digest()
            || binding.disclosure_domain_digest() != session.disclosure_domain_digest()
            || !binding.schema().admits(session.version())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
        }
        let cursor = Some(state.cursor());
        Ok(ProtectedWatchRequestScopeV1 {
            retained_gap: None,
            retained_state: Some(state),
            owner: self,
            session,
            binding,
            cursor,
            selection,
        })
    }

    /// Consumes the genuine gap into its actual owner/session resync loan.
    ///
    /// # Errors
    ///
    /// Returns the original epoch/audience/disclosure/schema binding refusal.
    pub fn begin_watch_resync_request_once_v1<'owner, 'session>(
        &'owner mut self,
        session: &'session AuthenticatedNodeSessionV1,
        resync: ProtectedWatchResyncRequiredV1,
    ) -> Result<ProtectedWatchRequestScopeV1<'owner, 'session>, InvalidMultiNodeProtocol> {
        if resync.binding.coordinator_epoch() != session.coordinator_epoch()
            || resync.binding.audience_digest() != session.audience_digest()
            || resync.binding.disclosure_domain_digest() != session.disclosure_domain_digest()
            || !resync.binding.schema().admits(session.version())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        let binding = resync.binding;
        Ok(ProtectedWatchRequestScopeV1 {
            retained_gap: Some(resync),
            retained_state: None,
            owner: self,
            session,
            binding,
            cursor: None,
            selection: WatchRequestSelectionV1::Resync,
        })
    }
}

impl ProtectedWatchRequestScopeV1<'_, '_> {
    /// Returns immutable binding DATA derived from the genuine native holder.
    #[must_use]
    pub const fn binding_v1(&self) -> NodeWatchBindingV1 {
        self.binding
    }

    /// Returns current cursor DATA when this loan retains actual watch replay.
    #[must_use]
    pub const fn cursor_v1(&self) -> Option<NodeWatchCursorV1> {
        self.cursor
    }

    /// Consumes the actual owner/session loan for exactly its old watch request.
    ///
    /// # Errors
    ///
    /// Returns a DATA mismatch or the original native issuer's typed refusal.
    pub fn prepare_once_v1(
        self,
        body: NodeRequestBodyV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        let _holders = (&self.retained_gap, &self.retained_state);
        let purpose: &'static [u8] = match self.selection {
            WatchRequestSelectionV1::Bootstrap => {
                if !matches!(&body, NodeRequestBodyV1::RelistAssignments { binding } if *binding == self.binding)
                {
                    return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
                }
                b"watch-bootstrap"
            }
            WatchRequestSelectionV1::Resync => {
                if !matches!(&body, NodeRequestBodyV1::RelistAssignments { binding } if *binding == self.binding)
                {
                    return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
                }
                b"watch-resync"
            }
            WatchRequestSelectionV1::Resume => {
                if !matches!(&body, NodeRequestBodyV1::Watch { after, maximum_events }
                    if Some(*after) == self.cursor && usize::from(*maximum_events) == MAX_WATCH_EVENTS)
                {
                    return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
                }
                b"watch-resume"
            }
            WatchRequestSelectionV1::Compaction => {
                let cursor = self
                    .cursor
                    .ok_or(InvalidMultiNodeProtocol::WatchBindingMismatch)?;
                // No allocation or caller flag can substitute another floor or
                // policy. The Coordinator still performs the original checked constructor.
                let expected = NodeWatchBindingV1::new(
                    self.binding.coordinator_epoch(),
                    cursor.event_sequence(),
                    cursor.last_event_uid(),
                    cursor.event_sequence(),
                    self.binding.query_digest(),
                    self.binding.authorization_digest(),
                    self.binding.audience_digest(),
                    self.binding.disclosure_domain_digest(),
                    self.binding.schema(),
                )?;
                if !matches!(&body, NodeRequestBodyV1::RelistAssignments { binding } if *binding == expected)
                {
                    return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
                }
                b"watch-compaction-resync"
            }
        };
        self.owner
            .prepare_outbound_request(self.session, body, purpose)
    }
}
