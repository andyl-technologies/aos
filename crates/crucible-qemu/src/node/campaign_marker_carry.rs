//! Campaign boundary markers carried until their deferred VMStop.
//!
//! The plugin defers a campaign marker's VMStop to its next icount
//! publication. A quantum can end between the marker callback and that
//! publication: the marker event is then drained with the ending quantum,
//! and only the physical stop arrives with the next one. The node retains
//! the latest drained campaign marker so the stop can still be proven
//! against it. A carried marker is advisory input to the exact-stop proof;
//! it never parks a node by itself.

use crucible::{ObservableEvent, ObservableEventPayload};

use super::QemuNode;

/// Guest markers at which campaign marker parking defers a VMStop.
pub(crate) const CAMPAIGN_BOUNDARY_MARKERS: [&str; 2] =
    ["fault.transport.ready", "fault.followup.ready"];

impl QemuNode {
    /// Retains the latest campaign boundary marker among drained `events`.
    pub(super) fn carry_campaign_markers(&mut self, events: &[ObservableEvent]) {
        let latest = events.iter().rev().find(|event| {
            matches!(
                event.payload(),
                ObservableEventPayload::GuestMarker { marker, .. }
                    if CAMPAIGN_BOUNDARY_MARKERS.contains(&marker.name.as_str())
            )
        });
        if let Some(event) = latest {
            self.carried_campaign_marker = Some(event.clone());
        }
    }

    /// Returns the campaign marker drained before its VMStop was observed.
    pub(crate) fn carried_campaign_marker(&self) -> Option<&ObservableEvent> {
        self.carried_campaign_marker.as_ref()
    }

    /// Drops the carried marker once a stop consumed or disproved it.
    pub(crate) fn forget_carried_campaign_marker(&mut self) {
        self.carried_campaign_marker = None;
    }
}
