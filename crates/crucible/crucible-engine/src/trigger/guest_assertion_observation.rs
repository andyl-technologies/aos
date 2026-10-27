//! Online evaluation of structured guest assertion observations.

use super::{
    GuestAssertionKind, GuestAssertionMarker, GuestMarkerAssertionState, HostAssertionOutcome,
    HostAssertionOutcomeKind, ObservableEvent, VirtualTime, guest_assertion_marker_event_evidence,
    guest_marker_payload_reason,
};

/// Observable events already applied to guest marker assertion states.
///
/// Applying a marker payload again leaves its state unchanged, so a cursor
/// that does not describe the supplied prefix costs only a rescan from the
/// start; it can never skip an unapplied marker.
#[derive(Clone, Debug)]
pub(super) struct ObservableEventCursor {
    applied: usize,
    last: Option<ObservableEvent>,
}

impl ObservableEventCursor {
    pub(super) fn at_end(events: &crate::History<ObservableEvent>) -> Self {
        Self {
            applied: events.len(),
            last: events.last().cloned(),
        }
    }

    /// Returns where `events` continues past this cursor, or zero when
    /// `events` does not extend the history the cursor was taken from.
    pub(super) fn resume_index(
        cursor: Option<&Self>,
        events: &crate::History<ObservableEvent>,
    ) -> usize {
        let Some(cursor) = cursor else {
            return 0;
        };
        let extends = match cursor.applied.checked_sub(1) {
            None => true,
            Some(last) => events.get(last) == cursor.last.as_ref(),
        };
        if extends { cursor.applied } else { 0 }
    }
}

pub(super) fn observe_guest_marker_assertion_state(
    state: &mut GuestMarkerAssertionState,
    at: VirtualTime,
    event: &ObservableEvent,
    marker: &GuestAssertionMarker,
) -> Option<HostAssertionOutcome> {
    if state.terminal.is_some() {
        return None;
    }

    if state
        .declared_message
        .as_ref()
        .is_some_and(|message| message != &marker.message)
    {
        return state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(
                marker,
                "guest marker assertion message differs from its scenario declaration",
            ),
            Some(guest_assertion_marker_event_evidence(event, marker)),
        );
    }

    if marker.kind != state.kind {
        return state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(
                marker,
                &format!(
                    "guest marker assertion kind mismatch: declared {:?}, observed {:?}",
                    state.kind, marker.kind
                ),
            ),
            Some(guest_assertion_marker_event_evidence(event, marker)),
        );
    }

    match state.kind {
        GuestAssertionKind::Always if !marker.condition => state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(marker, "guest always marker condition was false"),
            Some(guest_assertion_marker_event_evidence(event, marker)),
        ),
        GuestAssertionKind::Sometimes if marker.condition => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_payload_reason(marker, "guest sometimes marker became true"),
        ),
        GuestAssertionKind::Reachable if marker.condition => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_payload_reason(marker, "guest reachable marker was reached"),
        ),
        GuestAssertionKind::Unreachable if marker.condition => state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(marker, "guest unreachable marker was reached"),
            Some(guest_assertion_marker_event_evidence(event, marker)),
        ),
        GuestAssertionKind::Always
        | GuestAssertionKind::Sometimes
        | GuestAssertionKind::Reachable
        | GuestAssertionKind::Unreachable => None,
    }
}
