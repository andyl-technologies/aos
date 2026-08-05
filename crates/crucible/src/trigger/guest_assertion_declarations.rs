//! Scenario-catalog declarations for structured guest assertions.

use super::{
    AssertionDef, GuestAssertionKind, GuestAssertionMarker, GuestMarkerAssertionState,
    HostAssertionState, Icount, NodeId, Properties, Property, PropertyLifecycleState,
};
use crate::model::Predicate;

pub(super) fn partition_declared_assertions(
    properties: &Properties,
) -> (Vec<HostAssertionState>, Vec<GuestMarkerAssertionState>) {
    let mut states = Vec::new();
    let mut guest_marker_states = Vec::new();
    for assertion in properties.assertions() {
        if let Some(state) = GuestMarkerAssertionState::from_declared_assertion(assertion) {
            let index = guest_marker_states
                .binary_search_by(|candidate: &GuestMarkerAssertionState| {
                    candidate.id.cmp(&state.id)
                })
                .unwrap_or_else(|index| index);
            guest_marker_states.insert(index, state);
        } else {
            states.push(HostAssertionState::new(assertion));
        }
    }
    (states, guest_marker_states)
}

impl GuestMarkerAssertionState {
    fn from_declared_assertion(assertion: &AssertionDef) -> Option<Self> {
        let Property::Sometimes {
            predicate: Predicate::GuestMarker { marker },
        } = &assertion.property
        else {
            return None;
        };
        if marker.name != assertion.id.name {
            return None;
        }
        Some(Self {
            id: assertion.id.clone(),
            lifecycle: PropertyLifecycleState::Declared,
            message: assertion.message.clone(),
            kind: GuestAssertionKind::Sometimes,
            must_hit: true,
            details: Vec::new(),
            location: String::from("scenario.properties"),
            observed_true: false,
            last_icount: None,
            last_node: None,
            terminal: None,
            declared_message: Some(assertion.message.clone()),
        })
    }

    pub(super) fn observe_payload(
        &mut self,
        retired_icount: Icount,
        node: &NodeId,
        marker: &GuestAssertionMarker,
    ) {
        self.must_hit |= marker.must_hit;
        if self.declared_message.is_none() {
            self.message = marker.message.clone();
        }
        self.location = marker.location.clone();
        self.details = marker.details.clone();
        self.last_icount = Some(retired_icount);
        self.last_node = Some(node.clone());
        if self.lifecycle == PropertyLifecycleState::Declared {
            self.lifecycle = PropertyLifecycleState::Passing;
        }
        if marker.condition {
            self.observed_true = true;
        }
    }
}
