//! Online evaluation of structured guest assertion observations.

use super::{
    GuestAssertionKind, GuestAssertionMarker, GuestMarkerAssertionState, HostAssertionOutcome,
    HostAssertionOutcomeKind, ObservableEvent, VirtualTime, guest_assertion_marker_event_evidence,
    guest_marker_payload_reason,
};

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
