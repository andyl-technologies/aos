//! Scenario-catalog declarations for structured guest assertions.

use super::assertions::owned_storage::{copy_assertion_id, copy_node, copy_string, reserve_slot};
use super::{
    AssertionDef, GuestAssertionKind, GuestAssertionMarker, GuestMarkerAssertionState,
    HostAssertionState, Icount, NodeId, Properties, Property, PropertyLifecycleState,
    ReachabilityExpectation,
};
use crate::EngineError;
use crate::model::Predicate;

pub(super) fn partition_declared_assertions(
    properties: &Properties,
) -> Result<(Vec<HostAssertionState>, Vec<GuestMarkerAssertionState>), EngineError> {
    let mut states = Vec::new();
    let mut guest_marker_states = Vec::new();
    for assertion in properties.assertions() {
        if let Some(state) = GuestMarkerAssertionState::from_declared_assertion(assertion)? {
            let index = guest_marker_states
                .binary_search_by(|candidate: &GuestMarkerAssertionState| {
                    candidate.id.cmp(&state.id)
                })
                .unwrap_or_else(|index| index);
            reserve_slot(&mut guest_marker_states)?;
            guest_marker_states.insert(index, state);
        } else {
            reserve_slot(&mut states)?;
            states.push(HostAssertionState::new(assertion)?);
        }
    }
    Ok((states, guest_marker_states))
}

impl GuestMarkerAssertionState {
    fn from_declared_assertion(assertion: &AssertionDef) -> Result<Option<Self>, EngineError> {
        let (marker, kind, must_hit) = match &assertion.property {
            Property::Always {
                predicate: Predicate::GuestMarker { marker },
            } => (marker, GuestAssertionKind::Always, true),
            Property::Sometimes {
                predicate: Predicate::GuestMarker { marker },
            } => (marker, GuestAssertionKind::Sometimes, true),
            Property::Reachable {
                predicate: Predicate::GuestMarker { marker },
                expectation: ReachabilityExpectation::Reachable { on_unreached: _ },
            } => (marker, GuestAssertionKind::Reachable, true),
            Property::Reachable {
                predicate: Predicate::GuestMarker { marker },
                expectation: ReachabilityExpectation::Unreachable,
            } => (marker, GuestAssertionKind::Unreachable, false),
            Property::Eventually { .. }
            | Property::AfterQuiescence { .. }
            | Property::Always { .. }
            | Property::Sometimes { .. }
            | Property::Reachable { .. } => return Ok(None),
        };
        if marker.name != assertion.id.name {
            return Ok(None);
        }
        Ok(Some(Self {
            id: copy_assertion_id(&assertion.id)?,
            lifecycle: PropertyLifecycleState::Declared,
            message: copy_string(&assertion.message)?,
            kind,
            must_hit,
            details: Vec::new(),
            location: copy_string("scenario.properties")?,
            observed_true: false,
            last_icount: None,
            last_node: None,
            terminal: None,
            declared_message: Some(copy_string(&assertion.message)?),
        }))
    }

    pub(super) fn observe_payload(
        &mut self,
        retired_icount: Icount,
        node: &NodeId,
        marker: &GuestAssertionMarker,
    ) -> Result<(), EngineError> {
        let message = if self.declared_message.is_none() {
            Some(copy_string(&marker.message)?)
        } else {
            None
        };
        let location = copy_string(&marker.location)?;
        let details = super::assertions::owned_storage::copy_json(&marker.details)?;
        let node = copy_node(node)?;

        self.must_hit |= marker.must_hit;
        if let Some(message) = message {
            self.message = message;
        }
        self.location = location;
        self.details = details;
        self.last_icount = Some(retired_icount);
        self.last_node = Some(node);
        self.observed_true |= marker.condition;
        Ok(())
    }
}
